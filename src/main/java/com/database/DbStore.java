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
	private Connection con;
	private PreparedStatement pst;
	private String insertQuery;
	private int stackIndex;
	private final int STACK_CAP = 1000;
	
	
	public DbStore(){
        con = null;
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
        try {
			con = DriverManager.getConnection(url, user, password);
			Statement st = con.createStatement();
			st.executeUpdate("TRUNCATE packetinfo");
			con.setAutoCommit(false);
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean insertToDB(int packetNumber, Timestamp timestamp, 
			long srcAddress, int srcPort, long destAddress, int destPort, 
			int protocol, boolean ack, boolean syn){
		boolean result = true;
        try {
        	openConnection();
            
            pst.setInt(1, packetNumber);
            pst.setTimestamp(2, timestamp);
            pst.setLong(3, srcAddress);
            pst.setInt(4, srcPort);
            pst.setLong(5, destAddress);
            pst.setInt(6, destPort);
            pst.setInt(7, protocol);
            pst.setBoolean(8, ack);
            pst.setBoolean(9, syn);
            
            pst.addBatch();
            stackIndex++;
            
            if (stackIndex == STACK_CAP) {
            	pst.executeLargeBatch();
            	con.commit();
            	closeConnection();
            	stackIndex = 0;
            }
        } catch (SQLException ex) {
            Logger lgr = Logger.getLogger(DbStore.class.getName());
            lgr.log(Level.SEVERE, ex.getMessage(), ex);
            result = false;
        }
        return result;
    }
	
	public boolean commitRemainder() {
		boolean result = true;
		if (stackIndex > 0) {
			try {
				pst.executeLargeBatch();
				con.commit();
	        	closeConnection();
	        	stackIndex = 0;
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				result = false;
			}
        	
		}
		return result;
	}
	
	private void closeConnection() {
		 try {
             if (pst != null) {
                 pst.close();
             }
             if (con != null) {
                 con.close();
             }
         } catch (SQLException ex) {
             Logger lgr = Logger.getLogger(DbStore.class.getName());
             lgr.log(Level.SEVERE, ex.getMessage(), ex);
         }
	}
	
	private void openConnection() {
		try {
			if (con == null || con.isClosed()) {
				con = DriverManager.getConnection(url, user, password);
				con.setAutoCommit(false);
			}
			if (pst == null || pst.isClosed()) {
				pst = con.prepareStatement(insertQuery);
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}