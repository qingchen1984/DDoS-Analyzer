package com.analyzer;

import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Icmp.IcmpType;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import com.database.DbStore;

public class PcapFileLoader  implements Runnable {
	private static Logger logger;
	private DbStore dbStrore;
	private AtomicInteger progress;
	private String pcapFile;
	private int packetIndex;
	private int packetProcessed;
	private int ipV4Packets;
	private int ipV6Packets;
	private int tcpPackets;
	private int udpPackets;
	private int icmpPackets;
	private int unknownPackets;
	private int illegalPackets;
	private int tcpFloodPackets;
	private int udpFloodPackets;
	private int icmpFloodPackets;
	private int packetMax;
	private int packetsFailed;

	/**
	 * 
	 * Constructor
	 *
	 * @param pcapFileLocation
	 * @param dbName
	 * @param progress
	 * @param packetMax
	 */
	public PcapFileLoader(String pcapFileLocation, String dbName, AtomicInteger progress, int packetMax) {
		logger = LogManager.getLogger(PcapFileLoader.class);
		pcapFile = pcapFileLocation;
		packetIndex = 0;
		packetProcessed = 0;
		ipV4Packets = 0;
		ipV6Packets = 0;
		tcpPackets = 0;
		udpPackets = 0;
		icmpPackets = 0;
		unknownPackets = 0;
		illegalPackets = 0;
		tcpFloodPackets = 0;
		udpFloodPackets = 0;
		icmpFloodPackets = 0;
		packetsFailed = 0;
		this.progress = progress;
		progress.set(0);
		this.packetMax = packetMax;
		dbStrore = new DbStore(dbName, false);
	}


	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {
		long startTime = System.currentTimeMillis();
		
		progress.set(0);
		logger.info("Openning pcap file: " + pcapFile);
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final Pcap pcap = Pcap.openOffline(pcapFile, errbuf);  
        if (pcap == null) {  
        	logger.info(errbuf.toString()); // Error is stored in errbuf if any  
            return;  
        } 
        
        final PcapPacket packet = new PcapPacket(Type.POINTER); 
        final Ip4 ip4 = new Ip4();
    	final Tcp tcp = new Tcp();
    	final Icmp icmp = new Icmp();
		
		
        while (pcap.nextEx(packet) != Pcap.NEXT_EX_EOF) {
        	
        	packetIndex++;
        	
        	try {
        		if (packet.hasHeader(Tcp.ID)) {
        			try {
        				packet.getHeader(tcp);
        				if (tcp.flags_SYN() && tcp.flags_ACK()) {
            				tcpFloodPackets++;
            				packet.getHeader(ip4);
            				dbStrore.addToBatch(DbStore.TCP_FLOODING_TABLE_NAME,
            						new Timestamp(packet.getCaptureHeader().timestampInMillis()), 
            						ip4.source());
    						if (tcpFloodPackets % 100000 == 0) {
    							dbStrore.commitBatch(DbStore.TCP_FLOODING_TABLE_NAME);
    						}
            			}
        			} catch (Exception e) {
                		packetsFailed++;
                	}
        		} else if (packet.hasHeader(Icmp.ID)) {
        			try {
	        			packet.getHeader(icmp);
		        		if(icmp.hasSubHeader(IcmpType.ECHO_REPLY_ID)) {
		        			icmpFloodPackets++;
		        			packet.getHeader(ip4);
							dbStrore.addToBatch(DbStore.ICMP_FLOODING_TABLE_NAME, 
									new Timestamp(packet.getCaptureHeader().timestampInMillis()), 
									ip4.source());
							if (icmpFloodPackets % 100000 == 0) {
								dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
							}
		        		}
		        		if(icmp.hasSubHeader(IcmpType.DESTINATION_UNREACHABLE_ID)) {
		        			udpFloodPackets++;
		        			packet.getHeader(ip4);
							dbStrore.addToBatch(DbStore.UDP_FLOODING_TABLE_NAME,
									new Timestamp(packet.getCaptureHeader().timestampInMillis()), 
									ip4.source());
							if (udpFloodPackets % 100000 == 0) {
								dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
							}
		        		}
        			} catch (Exception e) {
                		packetsFailed++;
                	}
	        	} 
        	} catch (Exception e) {
        		logger.error("Error found while processing packet #" + packetIndex + " " + e.getCause() + e.getMessage()) ;
        		e.printStackTrace();
        		packetsFailed++;
        	}
        }  //end of while loop
        // inserts any remainder rows in batch to the DB
 		dbStrore.commitBatch(DbStore.TCP_FLOODING_TABLE_NAME);
 		dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
 		dbStrore.commitBatch(DbStore.ICMP_FLOODING_TABLE_NAME);
 		dbStrore.closeAllConnections();
 		packetProcessed = tcpFloodPackets + udpFloodPackets + icmpFloodPackets;
        
        long endTime = System.currentTimeMillis();
        logger.info("Total load time: " + (endTime - startTime)/1000 + " seconds");
        logger.info("Packets read: " + packetIndex);
		logger.info("Packets Processed: " + packetProcessed);
		logger.info("Packets Failed: " + packetsFailed);
		logger.info("TCP Flood packets Read: " + tcpFloodPackets);
		logger.info("UDP Flood packets Read: " + udpFloodPackets);
		logger.info("ICMP Flood packets Read: " + icmpFloodPackets);
        pcap.close();  
        progress.set(100);
	}


	/**
	 * Gets the value of packetIndex
	 *
	 * @return the packetIndex
	 */
	public int getPacketIndex() {
		return packetIndex;
	}


	/**
	 * Sets the value of packetIndex
	 *
	 * @param packetIndex the packetIndex to set
	 */
	public void setPacketIndex(int packetIndex) {
		this.packetIndex = packetIndex;
	}


	/**
	 * Gets the value of packetProcessed
	 *
	 * @return the packetProcessed
	 */
	public int getPacketProcessed() {
		return packetProcessed;
	}


	/**
	 * Sets the value of packetProcessed
	 *
	 * @param packetProcessed the packetProcessed to set
	 */
	public void setPacketProcessed(int packetProcessed) {
		this.packetProcessed = packetProcessed;
	}


	/**
	 * Gets the value of ipV4Packets
	 *
	 * @return the ipV4Packets
	 */
	public int getIpV4Packets() {
		return ipV4Packets;
	}


	/**
	 * Sets the value of ipV4Packets
	 *
	 * @param ipV4Packets the ipV4Packets to set
	 */
	public void setIpV4Packets(int ipV4Packets) {
		this.ipV4Packets = ipV4Packets;
	}


	/**
	 * Gets the value of ipV6Packets
	 *
	 * @return the ipV6Packets
	 */
	public int getIpV6Packets() {
		return ipV6Packets;
	}


	/**
	 * Sets the value of ipV6Packets
	 *
	 * @param ipV6Packets the ipV6Packets to set
	 */
	public void setIpV6Packets(int ipV6Packets) {
		this.ipV6Packets = ipV6Packets;
	}


	/**
	 * Gets the value of tcpPackets
	 *
	 * @return the tcpPackets
	 */
	public int getTcpPackets() {
		return tcpPackets;
	}


	/**
	 * Sets the value of tcpPackets
	 *
	 * @param tcpPackets the tcpPackets to set
	 */
	public void setTcpPackets(int tcpPackets) {
		this.tcpPackets = tcpPackets;
	}


	/**
	 * Gets the value of udpPackets
	 *
	 * @return the udpPackets
	 */
	public int getUdpPackets() {
		return udpPackets;
	}


	/**
	 * Sets the value of udpPackets
	 *
	 * @param udpPackets the udpPackets to set
	 */
	public void setUdpPackets(int udpPackets) {
		this.udpPackets = udpPackets;
	}


	/**
	 * Gets the value of icmpPackets
	 *
	 * @return the icmpPackets
	 */
	public int getIcmpPackets() {
		return icmpPackets;
	}


	/**
	 * Sets the value of icmpPackets
	 *
	 * @param icmpPackets the icmpPackets to set
	 */
	public void setIcmpPackets(int icmpPackets) {
		this.icmpPackets = icmpPackets;
	}


	/**
	 * Gets the value of unknownPackets
	 *
	 * @return the unknownPackets
	 */
	public int getUnknownPackets() {
		return unknownPackets;
	}


	/**
	 * Sets the value of unknownPackets
	 *
	 * @param unknownPackets the unknownPackets to set
	 */
	public void setUnknownPackets(int unknownPackets) {
		this.unknownPackets = unknownPackets;
	}


	/**
	 * Gets the value of illegalPackets
	 *
	 * @return the illegalPackets
	 */
	public int getIllegalPackets() {
		return illegalPackets;
	}


	/**
	 * Sets the value of illegalPackets
	 *
	 * @param illegalPackets the illegalPackets to set
	 */
	public void setIllegalPackets(int illegalPackets) {
		this.illegalPackets = illegalPackets;
	}


	/**
	 * Gets the value of tcpFloodPackets
	 *
	 * @return the tcpFloodPackets
	 */
	public int getTcpFloodPackets() {
		return tcpFloodPackets;
	}


	/**
	 * Sets the value of tcpFloodPackets
	 *
	 * @param tcpFloodPackets the tcpFloodPackets to set
	 */
	public void setTcpFloodPackets(int tcpFloodPackets) {
		this.tcpFloodPackets = tcpFloodPackets;
	}


	/**
	 * Gets the value of udpFloodPackets
	 *
	 * @return the udpFloodPackets
	 */
	public int getUdpFloodPackets() {
		return udpFloodPackets;
	}


	/**
	 * Sets the value of udpFloodPackets
	 *
	 * @param udpFloodPackets the udpFloodPackets to set
	 */
	public void setUdpFloodPackets(int udpFloodPackets) {
		this.udpFloodPackets = udpFloodPackets;
	}


	/**
	 * Gets the value of icmpFloodPackets
	 *
	 * @return the icmpFloodPackets
	 */
	public int getIcmpFloodPackets() {
		return icmpFloodPackets;
	}


	/**
	 * Sets the value of icmpFloodPackets
	 *
	 * @param icmpFloodPackets the icmpFloodPackets to set
	 */
	public void setIcmpFloodPackets(int icmpFloodPackets) {
		this.icmpFloodPackets = icmpFloodPackets;
	}


	/**
	 * Gets the value of packetMax
	 *
	 * @return the packetMax
	 */
	public int getPacketMax() {
		return packetMax;
	}


	/**
	 * Sets the value of packetMax
	 *
	 * @param packetMax the packetMax to set
	 */
	public void setPacketMax(int packetMax) {
		this.packetMax = packetMax;
	}


	/**
	 * Gets the value of packetsFailed
	 *
	 * @return the packetsFailed
	 */
	public int getPacketsFailed() {
		return packetsFailed;
	}


	/**
	 * Sets the value of packetsFailed
	 *
	 * @param packetsFailed the packetsFailed to set
	 */
	public void setPacketsFailed(int packetsFailed) {
		this.packetsFailed = packetsFailed;
	}

	
}
