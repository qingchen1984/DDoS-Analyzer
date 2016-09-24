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
	
	
	public DbStore(){
        con = null;
        pst = null;
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
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean insertToDB(int packetNumber, Timestamp timestamp, 
			String srcAddress, int srcPort, String destAddress, int destPort, 
			String protocol, boolean ack, boolean syn){
		boolean result = true;
        try {
            con = DriverManager.getConnection(url, user, password);
            pst = con.prepareStatement(insertQuery);
            pst.setInt(1, packetNumber);
            pst.setTimestamp(2, timestamp);
            pst.setString(3, srcAddress);
            pst.setInt(4, srcPort);
            pst.setString(5, destAddress);
            pst.setInt(6, destPort);
            pst.setString(7, protocol);
            pst.setBoolean(8, ack);
            pst.setBoolean(9, syn);
            
            pst.executeUpdate();

        } catch (SQLException ex) {
            Logger lgr = Logger.getLogger(DbStore.class.getName());
            lgr.log(Level.SEVERE, ex.getMessage(), ex);
            result = false;

        } finally {

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
        return result;
    }
}