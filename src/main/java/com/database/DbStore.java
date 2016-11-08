package com.database;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import org.apache.logging.log4j.Logger;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.Location;
import com.mysql.cj.jdbc.DatabaseMetaData;

import org.apache.logging.log4j.LogManager;

/**
 * Manages all functions related to the database.
 * 
 * @author aavalos
 *
 */
public class DbStore {
	public static final String TCP_FLOODING_TABLE_NAME = "tcpFlood";
	public static final String UDP_FLOODING_TABLE_NAME = "udpFlood";
	public static final String ICMP_FLOODING_TABLE_NAME = "icmpFlood";
	public static final String SUMMARY_TABLE_NAME = "summary";
	public static final String TOTAL_PACKETS_READ = "packetsTotal";
	public static final String TOTAL_PACKETS_PROCESSED = "packetsProcessed";
	public static final String TOTAL_IPV4_PACKETS = "packetsIpV4";
	public static final String TOTAL_IPV6_PACKETS = "packetsIpV6";
	public static final String TOTAL_TCP_PACKETS = "packetsTcp";
	public static final String TOTAL_UDP_PACKETS = "packetsUdp";
	public static final String TOTAL_ICMP_PACKETS = "packetsIcmp";
	public static final String TOTAL_UNKNOWN_PACKETS = "packetsUnknown";
	public static final String TOTAL_ILLEGAL_PACKETS = "packetsIllegal";
	public static final String TOTAL_TCP_FLOOD_PACKETS = "packetsTcpFlood";
	public static final String TOTAL_UDP_FLOOD_PACKETS = "packetsUdpFlood";
	public static final String TOTAL_ICMP_FLOOD_PACKETS = "packetsIcmpFlood";
	public static final String FILE_NAME = "fileName";
	public static final String FILE_SIZE = "fileSize";
	public static final String FILE_PROCESS_TIME = "processTime";
	private String url;
	private String urlNoDb;
	private String user;
	private String password;
	private PreparedStatement pstTcp;
	private PreparedStatement pstUdp;
	private PreparedStatement pstIcmp;
	private Connection con;
	private Logger logger;
	
	/**
	 * Constructor
	 * 
	 * @param dbName Database name to be used.
	 * @param createDB Flag determining if database should be created/cleared.
	 */
	public DbStore(String dbName, boolean createDB){
		logger = LogManager.getLogger(DbStore.class);
        url = "jdbc:mysql://localhost:3306/" + dbName + "?autoReconnect=true&useSSL=false";
        urlNoDb = "jdbc:mysql://localhost:3306/?autoReconnect=true&useSSL=false";
        user = "root";
        password = "password";
        if (createDB) setupDB(dbName);
	}
	
	/**
	 * Sets am existing database name to be used if none was specified during object creation.
	 * 
	 * @param dbName
	 */
	public void setDb(String dbName) {
		url = "jdbc:mysql://localhost:3306/" + dbName + "?autoReconnect=true&useSSL=false";
	}
	
	/**
	 * Adds parameters to a batch to be later inserted to the DB.
	 * 
	 * @param packetNumber
	 * @param timestamp
	 * @param srcAddress
	 * @param srcPort
	 * @param destAddress
	 * @param destPort
	 * @param protocol
	 * @param ack
	 * @param syn
	 * @return
	 */
	public boolean addToBatch(String tableName, Timestamp timestamp, byte[] srcAddress){
		boolean result = true;
        try {
        	openConnection();
            PreparedStatement pst = getPreparedStatement(tableName);
            if ( pst == null) { 
    			logger.error("addToBatch:: PreparedStatement found null for table name: " + tableName);
    			return false;
    		}
            pst.setTimestamp(1, timestamp);
            pst.setBytes(2, srcAddress);
            
            pst.addBatch();
            
        } catch (SQLException ex) {
            logger.error(ex.getMessage());
            result = false;
        }
        return result;
    }

	/**
	 * Gets the appropriate PreparedStatement according to the provided table name.
	 * 
	 * @param tableName Table name options from the class static variables.
	 * @return PreparedStatement corresponding to the provided table name.
	 */
	private PreparedStatement getPreparedStatement(String tableName) {
		PreparedStatement pst = null;
		switch(tableName) {
			case TCP_FLOODING_TABLE_NAME:
				pst = pstTcp;
				break;
			case UDP_FLOODING_TABLE_NAME:
				pst = pstUdp;
				break;
			case ICMP_FLOODING_TABLE_NAME:
				pst = pstIcmp;
				break;
			default:
				logger.error("Unrecognized table name: " + tableName);
		}
		return pst;
	}
	
	/**
	 * Commits batch for the table name provided.
	 * 
	 * @param tableName Table name options from the class static variables.
	 * @return true if the entire batch committed successfully, false otherwise.
	 */
	public boolean commitBatch(String tableName) {
		
		boolean result = false;
		//if (stackIndex <= 0) return result;
		PreparedStatement pst = getPreparedStatement(tableName);
		if ( pst == null) { 
			logger.error("commitBatch:: PreparedStatement found null for table name: " + tableName);
			return result;
		}
		try {
			long startTime = System.currentTimeMillis();
			long[] rs = pst.executeLargeBatch();
			con.commit();
			long endTime = System.currentTimeMillis();
			logger.debug("commitBatch - commited " + rs.length + " entries in " + (endTime - startTime)/1000 + " seconds.");
        	result = true;
		} catch (SQLException e) {
			logger.error(e.getMessage(), e);
		} finally {
			closePstConnection(pst);
		}
		return result;
	}
	
	/**
	 * Closes a PreparedStatement connection.
	 * 
	 * @param pst PreparedStatement to close.
	 */
	private void closePstConnection(PreparedStatement pst) {
		try {
			if (pst != null) {
				pst.close();
			}
		} catch (SQLException e) {
				logger.error(e.getMessage(), e);
			}
	}
	
	/**
	 * Closes all connections used for adding DOS data
	 */
	public void closeAllConnections() {
		 try {
             if (pstTcp != null) {
            	 pstTcp.close();
             }
             if (pstUdp != null) {
            	 pstUdp.close();
             }
             if (pstIcmp != null) {
            	 pstIcmp.close();
             }
             if (con != null) {
                 con.close();
             }
         } catch (SQLException e) {
        	 logger.error(e.getMessage(), e);
         }
	}
	
	/**
	 * Opens all connections used for adding DOS data
	 */
	private void openConnection() {
		try {
			if (con == null || con.isClosed()) {
					con = DriverManager.getConnection(url, user, password);
					con.setAutoCommit(false);
			}
			if (pstTcp == null || pstTcp.isClosed()) {
				pstTcp = con.prepareStatement(getInsertQueryForTable(TCP_FLOODING_TABLE_NAME));
			}
			if (pstUdp == null || pstUdp.isClosed()) {
				pstUdp = con.prepareStatement(getInsertQueryForTable(UDP_FLOODING_TABLE_NAME));
			}
			if (pstIcmp == null || pstIcmp.isClosed()) {
				pstIcmp = con.prepareStatement(getInsertQueryForTable(ICMP_FLOODING_TABLE_NAME));
			}
		} catch (SQLException e) {
			logger.error(e.getMessage(), e);
		}
	}
	
	/**
	 * Clears all DBs used for adding DOS data
	 * 
	 * @param dbName
	 * @param connection
	 * @throws SQLException
	 */
	private void clearDbTable(String dbName, Connection connection) throws SQLException {
		Statement st = null;
		st = connection.createStatement();
		st.executeUpdate("TRUNCATE " + dbName + "." + TCP_FLOODING_TABLE_NAME);
		st.executeUpdate("TRUNCATE " + dbName + "." + UDP_FLOODING_TABLE_NAME);
		st.executeUpdate("TRUNCATE " + dbName + "." + ICMP_FLOODING_TABLE_NAME);
		st.close();
	}
	
	/**
	 * Sets up database using the given name
	 * 
	 * @param dbName Name for database
	 */
	private void setupDB(String dbName) {
		Connection connection = null;
		try {
			// Create DB
			connection = DriverManager.getConnection(urlNoDb, user, password);
		    Statement  statement = connection.createStatement();
		    statement.executeUpdate("CREATE DATABASE IF NOT EXISTS " + dbName);
		    // Create tables
		    createTable(TCP_FLOODING_TABLE_NAME, dbName, connection);
		    createTable(UDP_FLOODING_TABLE_NAME, dbName, connection);
		    createTable(ICMP_FLOODING_TABLE_NAME, dbName, connection);
		    createSummaryTable(dbName, connection);
		    clearDbTable(dbName, connection);
		}
		catch (SQLException e) {
			logger.error("Database creation failed", e);
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					logger.error("Database close connection failed", e);
				}
			}
		}
	}
	
	/**
	 * Create a table using the given name and connection. 
	 * 
	 * @param tableName Name for table
	 * @param dbName DB name where to create the tables.
	 * @param connection Connection to be used
	 * @throws SQLException
	 */
	private void createTable(String tableName, String dbName, Connection connection) throws SQLException {
	    String sqlCreate = "CREATE TABLE IF NOT EXISTS " + dbName + "." + tableName
	            + "  (Id BIGINT(20) NOT NULL AUTO_INCREMENT,"
	            + "   Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
	            + "   SrcAddress VARBINARY(16),"
	            + "   PRIMARY KEY (`Id`))";

	    Statement stmt = connection.createStatement();
	    stmt.execute(sqlCreate);
	    stmt.close();
	}
	
	/**
	 * Creates a Summary table using the given database name and connection.
	 * 
	 * @param dbName Database name to use
	 * @param connection Connection to be used
	 * @throws SQLException
	 */
	private void createSummaryTable(String dbName, Connection connection) throws SQLException {
		String sqlCreate =
    		"CREATE TABLE IF NOT EXISTS " + dbName + "." + SUMMARY_TABLE_NAME + " ("
				+ FILE_NAME + " TEXT, "
				+ FILE_SIZE + " BIGINT, "
				+ FILE_PROCESS_TIME + " BIGINT, "
				+ TOTAL_PACKETS_READ + " BIGINT, "
				+ TOTAL_PACKETS_PROCESSED + " BIGINT, "
				+ TOTAL_IPV4_PACKETS + " BIGINT, "
				+ TOTAL_IPV6_PACKETS + " BIGINT, "
				+ TOTAL_TCP_PACKETS + " BIGINT, "
				+ TOTAL_UDP_PACKETS + " BIGINT, "
				+ TOTAL_ICMP_PACKETS + " BIGINT, "
				+ TOTAL_UNKNOWN_PACKETS + " BIGINT, "
				+ TOTAL_ILLEGAL_PACKETS + " BIGINT, "
				+ TOTAL_TCP_FLOOD_PACKETS + " BIGINT, "
				+ TOTAL_UDP_FLOOD_PACKETS + " BIGINT, "
				+ TOTAL_ICMP_FLOOD_PACKETS + " BIGINT )";
		    
	    Statement stmt = connection.createStatement();
	    stmt.execute(sqlCreate);
	    stmt.close();
	}

	/**
	 * Fills a summary table containing file/DB statistics after parsing.
	 * 
	 * @param fileName File name.
	 * @param fileSize File size.
	 * @param processTime Process time.
	 * @param packets Packet statistics.
	 */
	public void setSummaryTable(String fileName, long fileSize, 
			long processTime, HashMap<String, Long> packets) {
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
		    String sqlInsert =
		    	"INSERT INTO " + SUMMARY_TABLE_NAME + " ("
		    			+ FILE_NAME + "," + FILE_SIZE + "," + FILE_PROCESS_TIME + ","
	    				+ TOTAL_PACKETS_READ + "," + TOTAL_PACKETS_PROCESSED + ","
	    				+ TOTAL_IPV4_PACKETS + "," + TOTAL_IPV6_PACKETS + ","
	    				+ TOTAL_TCP_PACKETS + "," + TOTAL_UDP_PACKETS + ","
	    				+ TOTAL_ICMP_PACKETS + "," + TOTAL_UNKNOWN_PACKETS + ","
	    				+ TOTAL_ILLEGAL_PACKETS + "," + TOTAL_TCP_FLOOD_PACKETS + ","
	    				+ TOTAL_UDP_FLOOD_PACKETS + "," + TOTAL_ICMP_FLOOD_PACKETS + ") "
    				+ "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
		    
		    PreparedStatement preparedStmt = connection.prepareStatement(sqlInsert);
		    preparedStmt.setString(1, fileName);
		    preparedStmt.setLong(2, fileSize);
		    preparedStmt.setLong(3, processTime);
		    preparedStmt.setLong(4, packets.get(TOTAL_PACKETS_READ));
		    preparedStmt.setLong(5, packets.get(TOTAL_PACKETS_PROCESSED));
		    preparedStmt.setLong(6, packets.get(TOTAL_IPV4_PACKETS));
		    preparedStmt.setLong(7, packets.get(TOTAL_IPV6_PACKETS));
		    preparedStmt.setLong(8, packets.get(TOTAL_TCP_PACKETS));
		    preparedStmt.setLong(9, packets.get(TOTAL_UDP_PACKETS));
		    preparedStmt.setLong(10, packets.get(TOTAL_ICMP_PACKETS));
		    preparedStmt.setLong(11, packets.get(TOTAL_UNKNOWN_PACKETS));
		    preparedStmt.setLong(12, packets.get(TOTAL_ILLEGAL_PACKETS));
		    preparedStmt.setLong(13, packets.get(TOTAL_TCP_FLOOD_PACKETS));
		    preparedStmt.setLong(14, packets.get(TOTAL_UDP_FLOOD_PACKETS));
		    preparedStmt.setLong(15, packets.get(TOTAL_ICMP_FLOOD_PACKETS));
		    preparedStmt.execute();
		    preparedStmt.close();
		} catch (SQLException e) {
			logger.error("Database failed while creating summary table ", e);
		} finally {
			try {
				if (connection != null) {
					connection.close();
				}
			} catch (SQLException e) {
				logger.error("Database close connection failed", e);
			}
		}
	}
	
	/**
	 * Gets the summary and statistics for the file previously processed.
	 * The result will be populated in the input parameters.
	 * 
	 * @param fileName File name from the PCAP file that was processed.
	 * @param fileSize File size from the PCAP file that was processed.
	 * @param processTime Process time from the PCAP file that was processed.
	 * @param packets HashMap containing the packet statistics
	 * @return true if successful in getting the info, false otherwise.
	 */
	public boolean getSummaryTable(HashMap<String, Object> statistics) {
		boolean result = false;
		String query = "SELECT * FROM " + SUMMARY_TABLE_NAME + " LIMIT 1";
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			Statement  statement = connection.createStatement();
			ResultSet rs = statement.executeQuery(query);
			if(rs.next()) {
				statistics.put(FILE_NAME, rs.getString(FILE_NAME));
				statistics.put(FILE_SIZE, rs.getLong(FILE_SIZE));
				statistics.put(FILE_PROCESS_TIME, rs.getLong(FILE_PROCESS_TIME));
				statistics.put(TOTAL_PACKETS_READ, rs.getLong(TOTAL_PACKETS_READ));
				statistics.put(TOTAL_PACKETS_PROCESSED, rs.getLong(TOTAL_PACKETS_PROCESSED));
				statistics.put(TOTAL_IPV4_PACKETS, rs.getLong(TOTAL_IPV4_PACKETS));
				statistics.put(TOTAL_IPV6_PACKETS, rs.getLong(TOTAL_IPV6_PACKETS));
				statistics.put(TOTAL_TCP_PACKETS, rs.getLong(TOTAL_TCP_PACKETS));
				statistics.put(TOTAL_UDP_PACKETS, rs.getLong(TOTAL_UDP_PACKETS));
				statistics.put(TOTAL_ICMP_PACKETS, rs.getLong(TOTAL_ICMP_PACKETS));
				statistics.put(TOTAL_UNKNOWN_PACKETS, rs.getLong(TOTAL_UNKNOWN_PACKETS));
				statistics.put(TOTAL_ILLEGAL_PACKETS, rs.getLong(TOTAL_ILLEGAL_PACKETS));
				statistics.put(TOTAL_TCP_FLOOD_PACKETS, rs.getLong(TOTAL_TCP_FLOOD_PACKETS));
				statistics.put(TOTAL_UDP_FLOOD_PACKETS, rs.getLong(TOTAL_UDP_FLOOD_PACKETS));
				statistics.put(TOTAL_ICMP_FLOOD_PACKETS, rs.getLong(TOTAL_ICMP_FLOOD_PACKETS));
			    result = true;
			}
		} catch (SQLException e) {
			logger.error("Database failed", e);
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					logger.error("Database failed", e);
				}
			}
		}
		return result;
	}
	
	/**
	 * Gets the insert query for the given table name.
	 * 
	 * @param tableName Table name for the insert query.
	 * @return Insert string.
	 */
	private String getInsertQueryForTable(String tableName) {
		return "INSERT INTO " + tableName 
				+ "(Timestamp,SrcAddress) "
    		+ "VALUES(?,?)";
	}
	
	/**
	 * Query to be used to get a list of DOS victims and the amount of attack packets.
	 * 
	 * @param tableName Table name where to get the list from
	 * @param rate Lower bound rate of attack (packets per second) for each source address.
	 * @return Query
	 */
	private String getDosVictimsQuery(String tableName, int rate) {
		return "SELECT "
				+ "SrcAddress, "
				+ "COUNT(*) AS packetCount, "
				+ "(TIME_TO_SEC(MAX(TIMESTAMP)) - TIME_TO_SEC(MIN(TIMESTAMP))) AS totalSeconds, "
				+ "COUNT(*)/(TIME_TO_SEC(MAX(TIMESTAMP)) - TIME_TO_SEC(MIN(TIMESTAMP))) AS rate "
				+ "FROM " + tableName + " "
				+ "GROUP BY SrcAddress "
				+ "HAVING rate > " + rate;
	}
	
	/**
	 * Query to be used to get a list of attack rate (packets per second).
	 * 
	 * @param tableName Table name where to get the list from.
	 * @param rate Lower bound rate of attack (packets per second) for each source address.
	 * @return Query
	 */
	private String getAttackRateQuery(String tableName, int rate) {
		return "SELECT "
				+ "TIMESTAMP, "
				+ "COUNT(*) AS packetPerSecond "
				+ "FROM " + tableName + " "
				+ "WHERE EXISTS ("
				+ getDosVictimsQuery(tableName, rate) + ") "
				+ "GROUP BY TIMESTAMP";
	}
	
	private String getAttackRateForAddressQuery(String tableName) {
		return "SELECT "
				+ "TIMESTAMP, "
				+ "COUNT(*) AS packetPerSecond "
				+ "FROM " + tableName + " "
				+ "WHERE SrcAddress = ? "
				+ "GROUP BY TIMESTAMP";
	}
	
	/**
	 * Gets a list of attack rate (packets per second).
	 * 
	 * @param tableName Table name where to get the list from.
	 * @return List of attack rate
	 */
	public ArrayList<RateContent> getAttackRate(String tableName) {
		ArrayList<RateContent> rateArr = new ArrayList<RateContent>();
		String query = getAttackRateQuery(tableName, 20);
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			Statement  statement = connection.createStatement();
			ResultSet rs = statement.executeQuery(query);
			while (rs.next()) {
				rateArr.add(new RateContent(rs.getTimestamp("Timestamp").getTime(), rs.getInt("packetPerSecond")));
			}
		} catch (SQLException e) {
			logger.error("Database failed", e);
		}
		return rateArr;
	}
	
	public ArrayList<RateContent> getAttackRate(String tableName, byte[] address) {
		ArrayList<RateContent> rateArr = new ArrayList<RateContent>();
		String query = getAttackRateForAddressQuery(tableName);
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			PreparedStatement  ps = connection.prepareStatement(getAttackRateForAddressQuery(tableName));
			ps.setBytes(1, address);
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				rateArr.add(new RateContent(rs.getTimestamp("Timestamp").getTime(), rs.getInt("packetPerSecond")));
			}
		} catch (SQLException e) {
			logger.error("Database failed", e);
		}
		return rateArr;
	}
	
	/**
	 * Gets a list of DOS victims and the amount of attack packets.
	 * 
	 * @param tableName Table name where to get the list from.
	 * @return List of DOS victims and the amount of attack packets.
	 */
	public ArrayList<RowContent> getDosVictims(String tableName) {
		ArrayList<RowContent> resultArr = new ArrayList<RowContent>();
		String query = getDosVictimsQuery(tableName, 20);
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			Statement  statement = connection.createStatement();
			ResultSet rs = statement.executeQuery(query);
			File dbFile = new File("lib/GeoLite2-City/GeoLite2-City.mmdb");
			DatabaseReader reader = null;
			try {
				reader = new DatabaseReader.Builder(dbFile).build();
			} catch (IOException e) {
				logger.error("Error found while loading Geo-location database", e.getMessage());
			}
			CityResponse response;
			String country;
			String city;
			double latitude;
			double longitude;
			Location location;
			while (rs.next()) {
				InetAddress ip = null;
				String address = "Unknown";
				byte[] srcByteArr = rs.getBytes("SrcAddress");
				try {
					ip = InetAddress.getByAddress(srcByteArr);
					address = ip.getHostAddress();
				} catch (UnknownHostException e) {
					logger.error("Error encountered parsing byte[] address ", e.getMessage());
				}
				response = null;
				country = "Unknown";
				city = "Unknown";
				latitude = 0;
				longitude = 0;
				location = null;
				try {
					response = reader.city(ip);
					country = response.getCountry().getName();
					city = response.getCity().getName();
					if (city == null || city == "") city = "Unknown";
					location = response.getLocation();
					latitude = location.getLatitude();
					longitude = location.getLongitude();
				} catch (IOException | GeoIp2Exception e) {
					logger.error("Error encountered parsing country/city/location ", e.getMessage());
				}
				resultArr.add(new RowContent(
						srcByteArr,
						address,
						rs.getLong("packetCount"),
						rs.getLong("totalSeconds"),
						country, city, latitude, longitude));
			}
		} catch (SQLException e) {
			logger.error("Database failed", e);
			return null;
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					logger.error("Database failed", e);
				}
			}
		}
		return resultArr;
	}
	
	/**
	 * Gets all the database names
	 * 
	 * @return Array containing the database names
	 */
	public String[] getAllDataBaseNames() {
		ArrayList<String> result = new ArrayList<String>();
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(urlNoDb, user, password);
			DatabaseMetaData meta = (DatabaseMetaData) connection.getMetaData();
			ResultSet rs = meta.getCatalogs();
			while (rs.next()) {
				result.add(rs.getString("TABLE_CAT"));
			}
		} catch (SQLException e) {
			logger.error("Database failed", e);
			return null;
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (SQLException e) {
					logger.error("Database failed", e);
				}
			}
		}
		return result.toArray(new String[result.size()]);
	}
}