package com.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.logging.Level;
import java.util.logging.Logger;


public class DbStore {
	private String url;
	private String user;
	private String password;
	private PreparedStatement pst;
	private String insertQuery;
	private int stackIndex;
	private int STACK_CAP = 250000; //default value
	private boolean autoCommit = false;
	private Logger lgr;
	
	
	public DbStore(boolean autoCommit, int cap){
		lgr = Logger.getLogger(DbStore.class.getName());
        pst = null;
        stackIndex = 0;
        url = "jdbc:mysql://localhost:3306/dataanalyzer?autoReconnect=true&useSSL=false";
        user = "root";
        password = "password";
        insertQuery = "INSERT INTO packetinfo(PacketNumber,"
        					+ "Timestamp,SrcAddress,SrcPort,"
			        		+ "DestAddress,DestPort,"
			        		+ "Protocol,Ack,Syn) "
		        		+ "VALUES(?,?,?,?,?,?,?,?,?)";
        STACK_CAP = cap;
        this.autoCommit = autoCommit;
	}
	
	public boolean insertToDB(long packetNumber, Timestamp timestamp, 
			byte[] srcAddress, int srcPort, byte[] destAddress, int destPort, 
			int protocol, boolean ack, boolean syn){
		boolean result = true;
        try {
        	openConnection();
            
            pst.setLong(1, packetNumber);
            pst.setTimestamp(2, timestamp);
            pst.setBytes(3, srcAddress);
            pst.setInt(4, srcPort);
            pst.setBytes(5, destAddress);
            pst.setInt(6, destPort);
            pst.setInt(7, protocol);
            pst.setBoolean(8, ack);
            pst.setBoolean(9, syn);
            
            pst.addBatch();
            stackIndex++;
            
            if (autoCommit && stackIndex == STACK_CAP) {
            	commitBatch();
            }
        } catch (SQLException ex) {
            lgr.log(Level.SEVERE, ex.getMessage(), ex);
            result = false;
        }
        return result;
    }
	
	public boolean commitBatch() {
		boolean result = false;
		if (stackIndex <= 0) return result;
		try {
			pst.executeLargeBatch();
			pst.getConnection().commit();
        	lgr.log(Level.INFO, "commitBatch commited " + stackIndex + " entries.");
        	stackIndex = 0;
        	result = true;
		} catch (SQLException e) {
            lgr.log(Level.SEVERE, e.getMessage(), e);
		} finally {
			closeConnection();
		}
		return result;
	}
	
	private void closeConnection() {
		Connection con = null;
		 try {
             if (pst != null) {
            	 con = pst.getConnection();
                 pst.close();
             }
             if (con != null) {
                 con.close();
             }
         } catch (SQLException ex) {
             lgr.log(Level.SEVERE, ex.getMessage(), ex);
         }
	}
	
	private void openConnection() {
		try {
			if (pst == null || pst.isClosed()) {
				Connection connection = DriverManager.getConnection(url, user, password);
				connection.setAutoCommit(false);
				pst = connection.prepareStatement(insertQuery);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	
	public void clearDbTable() {
		Connection connection = null;
		Statement st = null;
		try {
			connection = DriverManager.getConnection(url, user, password);
			st = connection.createStatement();
			st.executeUpdate("TRUNCATE packetinfo");
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			try {
				if (st != null) st.close();
				if (connection != null) connection.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
	}
}