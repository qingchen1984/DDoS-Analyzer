package com.analyzer;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.FragmentedPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6Packet.IpV6Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.util.IpV4Helper;

import com.database.DbStore;

/**
 * @author aavalos
 *
 */
@SuppressWarnings("javadoc")
public class PcapReader implements Runnable {
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

	/**
	 * 
	 * Constructor
	 *
	 * @param pcapFileLocation
	 * @param dbName
	 * @param progress
	 * @param packetMax
	 */
	PcapReader(String pcapFileLocation, String dbName, AtomicInteger progress, int packetMax) {
		logger = LogManager.getLogger(PcapReader.class);
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
		this.progress = progress;
		this.packetMax = packetMax;
		dbStrore = new DbStore(dbName, false);
	}

	/**
	 * Gets the value of pcapFile
	 *
	 * @return the pcapFile
	 */
	public String getPcapFile() {
		return pcapFile;
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
	 * Gets the value of packetProcessed
	 *
	 * @return the packetProcessed
	 */
	public int getPacketProcessed() {
		return packetProcessed;
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
	 * Gets the value of ipV6Packets
	 *
	 * @return the ipV6Packets
	 */
	public int getIpV6Packets() {
		return ipV6Packets;
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
	 * Gets the value of udpPackets
	 *
	 * @return the udpPackets
	 */
	public int getUdpPackets() {
		return udpPackets;
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
	 * Gets the value of unknownPackets
	 *
	 * @return the unknownPackets
	 */
	public int getUnknownPackets() {
		return unknownPackets;
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
	 * Gets the value of tcpFloodPackets
	 *
	 * @return the tcpFloodPackets
	 */
	public int getTcpFloodPackets() {
		return tcpFloodPackets;
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
	 * Gets the value of icmpFloodPackets
	 *
	 * @return the icmpFloodPackets
	 */
	public int getIcmpFloodPackets() {
		return icmpFloodPackets;
	}

	@Override
	public void run() {
		
		PcapHandle handle = null;
		logger.info("Openning pcap file: " + pcapFile);
		try {
			handle = Pcaps.openOffline(pcapFile, TimestampPrecision.NANO);
		} catch (PcapNativeException e) {
			try {
				handle = Pcaps.openOffline(pcapFile);
			} catch (PcapNativeException e1) {
				logger.error(e1.getLocalizedMessage());
			}
		}

		Packet packet = null;
		logger.info("Parsing pcap file: " + pcapFile);
		long startTime = System.currentTimeMillis();
		for (;;) {
			//Update the progress
			int progressVal = (int) (((double) packetIndex) / packetMax * 100);
			progress.set(progressVal);
			try {
				packet = handle.getNextPacketEx();
				packetIndex++;
						
				if (packet.contains(TcpPacket.class)) {
					tcpPackets++;
					TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
					IpV4Header ip4header = packet.get(IpV4Packet.class).getHeader();
					/**
					 *  TCP flooding 
					 *  when ACK and SYN are true 
					 */
					if (tcpHeader.getAck() && tcpHeader.getSyn()) { 
						tcpFloodPackets ++;
						dbStrore.addToBatch(DbStore.TCP_FLOODING_TABLE_NAME, handle.getTimestamp(), ip4header.getSrcAddr().getAddress());
						packetProcessed++;
						
						if (tcpFloodPackets % 100000 == 0) {
							dbStrore.commitBatch(DbStore.TCP_FLOODING_TABLE_NAME);
						}
					}
				} else if (packet.contains(IcmpV4CommonPacket.class)) {
					icmpPackets++;
					IcmpV4CommonHeader icmpHeader = packet.get(IcmpV4CommonPacket.class).getHeader();
					/**
					 *  UDP flooding 
					 *  when finding a reply with an ICMP Destination Unreachable packet.
					 */
					if (icmpHeader.getType() == IcmpV4Type.DESTINATION_UNREACHABLE){
						udpFloodPackets++;
						IpV4Header ip4header = packet.get(IpV4Packet.class).getHeader();
						dbStrore.addToBatch(DbStore.UDP_FLOODING_TABLE_NAME, handle.getTimestamp(), ip4header.getSrcAddr().getAddress());
						packetProcessed++;
						
						if (udpFloodPackets % 100000 == 0) {
							dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
						}
					} 
					/**
					 *  ICMP flooding 
					 *  when finding an echo reply packet
					 */
					if(icmpHeader.getType() == IcmpV4Type.ECHO_REPLY){
						icmpFloodPackets++;
						IpV4Header ip4header = packet.get(IpV4Packet.class).getHeader();
						dbStrore.addToBatch(DbStore.ICMP_FLOODING_TABLE_NAME, handle.getTimestamp(), ip4header.getSrcAddr().getAddress());
						packetProcessed++;
						
						if (icmpFloodPackets % 100000 == 0) {
							dbStrore.commitBatch(DbStore.ICMP_FLOODING_TABLE_NAME);
						}
					}
				} 
			} catch (EOFException e) {
				logger.info("EOF");
				break;
			} catch (Exception e) {
				packetIndex++;
				logger.error("error found on packet: #"+ packetIndex + " " + e.getLocalizedMessage());
				e.printStackTrace();
			}
		} // end of for loop

		// inserts any remainder rows in batch to the DB
		dbStrore.commitBatch(DbStore.TCP_FLOODING_TABLE_NAME);
		dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
		dbStrore.commitBatch(DbStore.ICMP_FLOODING_TABLE_NAME);
		dbStrore.closeAllConnections();
		
		long endTime = System.currentTimeMillis();
		logger.debug("Total load time: " + (endTime - startTime) / 1000 + " seconds");
		logger.debug("Packets read: " + packetIndex);
		logger.debug("Packets processed: " + packetProcessed);
		handle.close();
		// Just in case we are setting this as completed.
		progress.set(100);
	}

}