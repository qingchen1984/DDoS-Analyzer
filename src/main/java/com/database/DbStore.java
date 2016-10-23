package com.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

import org.apache.logging.log4j.Logger;
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
	 * @param createDB Flag determining if database should be created.
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
	
	private void closePstConnection(PreparedStatement pst) {
		try {
			if (pst != null) {
				pst.close();
			}
		} catch (SQLException e) {
				logger.error(e.getMessage(), e);
			}
	}
	
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
	
	public void clearDbTable() {
		Connection connection = null;
		Statement st = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			st = connection.createStatement();
			st.executeUpdate("TRUNCATE " + TCP_FLOODING_TABLE_NAME);
			st.executeUpdate("TRUNCATE " + UDP_FLOODING_TABLE_NAME);
			st.executeUpdate("TRUNCATE " + ICMP_FLOODING_TABLE_NAME);
		} catch (SQLException e) {
			logger.error(e.getMessage(), e);
		} finally {
			try {
				if (st != null) st.close();
				if (connection != null) connection.close();
			} catch (SQLException e) {
				logger.error(e.getMessage(), e);
			}
		}
		
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
		}
		catch (SQLException e) {
			logger.error("Database creation failed", e);
		    e.printStackTrace();
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
}