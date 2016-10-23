package com.analyzer;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.sql.Date;
import java.sql.Timestamp;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.database.DbStore;

public class PcapFileLoader {
	
	
	//private static String srcPcapFile = "C:\\Users\\aavalos\\Downloads\\dataset.pcap";
	private static String srcPcapFile = "C:\\Temp\\dataset.pcap.Packets_0.pcap";
	//private static String srcPcapFile = "C:\\Users\\aavalos\\Documents\\test500.pcap";


	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Logger logger = LogManager.getLogger();
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        System.out.printf("Opening file for reading: %s%n", srcPcapFile);  
  
        final Pcap pcap = Pcap.openOffline(srcPcapFile, errbuf);  
        if (pcap == null) {  
        	logger.info(errbuf.toString()); // Error is stored in errbuf if any  
            return;  
        } 
        
        File f = new File(srcPcapFile);
        DbStore dbStrore = new DbStore(f.getName(), false);
        //dbStrore.clearDbTable();
        
        // Statistics
        long packetsProcessed = 0;
		long packetsRead = 0;
		long packetsFailed = 0;
		long tcpPacketsRead = 0;
		long udpPacketsRead = 0;
        
		
        long startTime = System.currentTimeMillis();
        final PcapPacket packet = new PcapPacket(Type.POINTER); 
        int packetResult = 0;
        
        Ip4 ip4 = new Ip4();
    	Tcp tcp = new Tcp();
    	Udp udp = new Udp();
    	Icmp icmp = new Icmp();
		byte[] srcAddress = null;
		byte[] destAddress = null;
		int protocol = 0;
		int srcPort = -1;
		int destPort = -1;
		boolean ack = false;
		boolean syn = false;
		

        while ((packetResult = pcap.nextEx(packet)) != Pcap.NEXT_EX_EOF) {
        	packetsRead++;
        	if (packetResult != 1) {
    			logger.error("Error found while getting next packet #" + packetsRead);
    			continue;
    		}
        	
        	try {
        		if (packet.hasHeader(Tcp.ID)) {
        			tcpPacketsRead++;
        		} else if (packet.hasHeader(Udp.ID)) {
        			packet.getHeader(udp);
        			if (!udp.isFragmented()) {
        				udpPacketsRead++;
        			}
	        	} else if (packet.hasHeader(Icmp.ID)) {
	        		
	        	} 
        		packetsProcessed++;
        	} catch (Exception e) {
        		logger.error("Error found while processing packet #" + packetsRead + " " + e.getCause());
        		packetsFailed++;
        	}
        } 

        
        
        /*************************************************************************** 
         * Third we create a packet handler which will receive packets from the 
         * libpcap loop. 
         **************************************************************************/  
		/*
        PcapPacketHandler<DbStore> jpacketHandler = new PcapPacketHandler<DbStore>() {
            public void nextPacket(PcapPacket packet, DbStore dbStrore) {  
            	
            	byte[] srcIp;
    			byte[] destIp;
    			Timestamp stamp = new Timestamp(packet.getCaptureHeader().timestampInMillis());
    			long packetNumber = packet.getFrameNumber();
    			
            	if(packet.hasHeader(ip4)) {
            		
    				srcIp = ip4.source();
    				destIp = ip4.destination();
					
            		if (packet.hasHeader(tcp)) {
            			
            			/*
            			dbStrore.addToBatch(packetNumber, stamp, 
            					srcIp, tcp.source(),
            					destIp, tcp.destination(), 
            	        		1, tcp.flags_ACK(), tcp.flags_SYN());
            	        		*
            		} else if (packet.hasHeader(udp)) {
            			
            			/*
            			dbStrore.addToBatch(packetNumber, stamp, 
            					srcIp, udp.source(),
            					destIp, udp.destination(), 
            	        		2, false, false);
            	        		*
            		} else {
            			//logger.info("IP Header not parsed. Packet #" + packetNumber );
            		}
            		
            	}
  
            }  
        };
        
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, dbStrore);
        */
        long endTime = System.currentTimeMillis();
        logger.info("Total load time: " + (endTime - startTime)/1000 + " seconds");
        logger.info("Packets read: " + packetsRead);
		logger.info("Packets Processed: " + packetsProcessed);
		logger.info("Packets Failed: " + packetsFailed);
		logger.info("TCP packets Read: " + tcpPacketsRead);
		logger.info("UDP packets Read: " + udpPacketsRead);
        pcap.close();  
        //dbStrore.commitBatch();

	}

}
