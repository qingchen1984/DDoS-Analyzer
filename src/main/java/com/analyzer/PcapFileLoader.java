package com.analyzer;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.sql.Date;
import java.sql.Timestamp;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.database.DbStore;

public class PcapFileLoader {
	
	private static final String PCAP_FILE_KEY = 
			PcapFileLoader.class.getName() + ".pcapFile";
	private static final String PCAP_FILE = 
			System.getProperty(PCAP_FILE_KEY, "src/main/resources/test500.pcap");


	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Logger logger = LoggerFactory.getLogger(PcapFileLoader.class);
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        System.out.printf("Opening file for reading: %s%n", PCAP_FILE);  
  
        final Pcap pcap = Pcap.openOffline(PCAP_FILE, errbuf);  
        if (pcap == null) {  
        	logger.info(errbuf.toString()); // Error is stored in errbuf if any  
            return;  
        } 
        
        /*************************************************************************** 
         * Third we create a packet handler which will receive packets from the 
         * libpcap loop. 
         **************************************************************************/  
        
        PcapPacketHandler<DbStore> jpacketHandler = new PcapPacketHandler<DbStore>() {
            public void nextPacket(PcapPacket packet, DbStore dbStrore) {  
            	Ip4 ip = new Ip4();
            	Tcp tcp = new Tcp();
            	Udp udp = new Udp();
            	byte[] srcIp;
    			byte[] destIp;
    			Timestamp stamp = new Timestamp(packet.getCaptureHeader().timestampInMillis());
    			long packetNumber = packet.getFrameNumber();
    			
            	if(packet.hasHeader(ip)) {
            		
    				srcIp = ip.source();
    				destIp = ip.destination();
					
            		if (packet.hasHeader(tcp)) {
            			dbStrore.insertToDB(packetNumber, stamp, 
            					srcIp, tcp.source(),
            					destIp, tcp.destination(), 
            	        		1, tcp.flags_ACK(), tcp.flags_SYN());
            		} else if (packet.hasHeader(udp)) {
            			dbStrore.insertToDB(packetNumber, stamp, 
            					srcIp, udp.source(),
            					destIp, udp.destination(), 
            	        		2, false, false);
            		} else {
            			logger.info("IP Header not parsed. Packet #" + packetNumber );
            		}
            		
            	}
  
            }  
        };  
  
        /*************************************************************************** 
         * Fourth we enter the loop and tell it to capture 10 packets. The loop 
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which 
         * is needed by JScanner. The scanner scans the packet buffer and decodes 
         * the headers. The mapping is done automatically, although a variation on 
         * the loop method exists that allows the programmer to sepecify exactly 
         * which protocol ID to use as the data link type for this pcap interface. 
         **************************************************************************/  
        DbStore dbStrore = new DbStore(false, 0);
        dbStrore.clearDbTable();
        long startTime = System.currentTimeMillis();
        try {  
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, dbStrore);  
            
        } finally {  
        	dbStrore.commitBatch();
        /*************************************************************************** 
         * Last thing to do is close the pcap handle 
         **************************************************************************/  
        	long endTime = System.currentTimeMillis();
            logger.info("Total load time: " + (endTime - startTime)/1000 + " seconds");
        	pcap.close();  
        }
        
	}

}
