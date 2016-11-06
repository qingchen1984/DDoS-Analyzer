package com.analyzer;

import java.io.EOFException;
import java.io.File;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.NotOpenException;
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
import org.pcap4j.packet.Packet.Header;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.IpV4Helper;

import com.database.DbStore;

@SuppressWarnings("javadoc")
public class PcapReader implements Runnable {
	private static Logger logger;

	private final static int TCP = IpNumber.TCP.hashCode();
	private final static int ICMPV4 = IpNumber.ICMPV4.hashCode();
	private final static int UDP = IpNumber.UDP.hashCode();
	private int packetIndex;
	private int packetProcessed;
	private int ipV4Packets;
	private int ipV6Packets;
	private int tcpPackets;
	private int udpPackets;
	private int icmpPackets;
	private int unknownPackets;
	private int illegalPackets;
	public volatile int progress;
	public int totalPackets;
	public int tcpFloodPackets;
	public int udpFloodPackets;
	public int icmpFloodPackets;
	private DbStore dbStrore;

	private String pcapFile;

	PcapReader(String pcapFileLocation, String dbName) {
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
		dbStrore = new DbStore(dbName, false);
	}
	
	public int getPacketsRead() {
		return packetIndex;
	}
	
	public int getPacketsProcessed() {
		return packetProcessed;
	}
	
	public int getIpV4pPacketsRead() {
		return ipV4Packets;
	}
	
	public int getIpV6pPacketsRead() {
		return ipV6Packets;
	}
	
	public int getTcpPacketsRead() {
		return tcpPackets;
	}
	
	public int getUdpPacketsRead() {
		return udpPackets;
	}
	
	public int getIcmpPacketsRead() {
		return icmpPackets;
	}
	
	public int getUnknownPacketsRead() {
		return unknownPackets;
	}
	
	public int getIllegalPacketsRead() {
		return illegalPackets;
	}
	
	public int getTcpFloodPacketsRead() {
		return tcpFloodPackets;
	}
	
	public int getUdpFloodPacketsRead() {
		return udpFloodPackets;
	}
	
	public int getIcmpFloodPacketsRead() {
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

		Map<Short, List<IpV4Packet>> ipV4Fragments = new HashMap<Short, List<IpV4Packet>>();

		Packet packet = null;
		Timestamp tstmp = handle.getTimestamp();
		byte[] srcAddress = null;
		byte[] destAddress = null;
		int protocol = 0;
		int srcPort = -1;
		int destPort = -1;
		boolean ack = false;
		boolean syn = false;
		logger.info("Parsing pcap file: " + pcapFile);
		long startTime = System.currentTimeMillis();
		for (;;) {
			try {
				packet = handle.getNextPacketEx();
				packetIndex++;
				
				tstmp =handle.getTimestamp();
				srcAddress = null;
				destAddress = null;
				protocol = 0;
				srcPort = -1;
				destPort = -1;
				ack = false;
				syn = false;
				
				if (packet.contains(IpV4Packet.class)) {
					ipV4Packets++;
					IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
					IpV4Header ip4header = ipV4Packet.getHeader();
					srcAddress = ip4header.getSrcAddr().getAddress();
					destAddress = ip4header.getDstAddr().getAddress();
					protocol = ip4header.getProtocol().hashCode();
					//handle fragments
					if (packet.contains(FragmentedPacket.class)) {
						short id = ip4header.getIdentification();
						if (ipV4Fragments.containsKey(id)) {// add fragment to list
							ipV4Fragments.get(id).add(ipV4Packet);
						} else {// start a new fragmented list
							List<IpV4Packet> list = new ArrayList<IpV4Packet>();
							list.add(ipV4Packet.get(IpV4Packet.class));
							ipV4Fragments.put(id, list);
						}
						if (!ip4header.getMoreFragmentFlag()) {
							ipV4Packet = IpV4Helper.defragment(ipV4Fragments.get(id));
							ip4header = ipV4Packet.getHeader();
							ipV4Fragments.remove(id);
						}
					} 
					
					if (!packet.contains(FragmentedPacket.class)) {
						
						if (packet.contains(TcpPacket.class)) {
							tcpPackets++;
							TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
							ack = tcpHeader.getAck();
							syn = tcpHeader.getSyn();
							
							// TCP flooding when ACK and SYN are true 
							if (ack == true && syn == true) { 
								tcpFloodPackets ++;
								dbStrore.addToBatch(DbStore.TCP_FLOODING_TABLE_NAME, tstmp, srcAddress);
								packetProcessed++;
								
								if (tcpFloodPackets % 100000 == 0) {
									dbStrore.commitBatch(DbStore.TCP_FLOODING_TABLE_NAME);
								}
							}
						} else if (packet.contains(UdpPacket.class)) {
							udpPackets++;
						} else if (packet.contains(IcmpV4CommonPacket.class)) {
							icmpPackets++;
							IcmpV4CommonHeader icmpHeader = packet.get(IcmpV4CommonPacket.class).getHeader();
							// UDP flooding when finding a reply with an ICMP Destination Unreachable packet.
							if (icmpHeader.getType() == IcmpV4Type.DESTINATION_UNREACHABLE){
								udpFloodPackets++;
								dbStrore.addToBatch(DbStore.UDP_FLOODING_TABLE_NAME, tstmp, srcAddress);
								packetProcessed++;
								
								if (udpFloodPackets % 100000 == 0) {
									dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
								}
							} 
							// ICMP flooding when finding an 
							else if(icmpHeader.getType() == IcmpV4Type.ECHO_REPLY){
								icmpFloodPackets++;
								dbStrore.addToBatch(DbStore.ICMP_FLOODING_TABLE_NAME, tstmp, srcAddress);
								packetProcessed++;
								
								if (icmpFloodPackets % 100000 == 0) {
									dbStrore.commitBatch(DbStore.UDP_FLOODING_TABLE_NAME);
								}
							}
						} else if (packet.contains(UnknownPacket.class)) {
							unknownPackets++;
							//System.out.println(ipV4Packet.get(UnknownPacket.class).getBuilder().build());
						} else if (packet.contains(IllegalPacket.class)) {
							illegalPackets++;
							//System.out.println(ipV4Packet.get(IllegalPacket.class).getBuilder().build());
						} else {
							logger.warn("IPV4 Protocol not recognized: " + ip4header.getProtocol().toString() + " #" + packetIndex);
							Iterator<Packet> iterator = packet.iterator();
							while (iterator.hasNext()) {
								logger.warn("Class found: " + iterator.next().getClass().getName());
							}
						}
					}
				} else if (packet.contains(IpV6Packet.class)) {
					ipV4Packets++;
					IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
					IpV6Header ip6header = ipV6Packet.getHeader();
					srcAddress = ip6header.getSrcAddr().getAddress();
					destAddress = ip6header.getDstAddr().getAddress();
					if (ipV6Packet.contains(TcpPacket.class)) {
						tcpPackets++;
						//logger.info("IPV6 packet contains TCP");
					} else if (ipV6Packet.contains(UdpPacket.class)) {
						udpPackets++;
						//logger.info("IPV6 packet contains UDP");
					} else if (ipV6Packet.contains(IcmpV6CommonPacket.class)) {
						icmpPackets++;
					} else {
						logger.warn("did not recognize IPV6 packet "  + " #" + packetIndex);
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
	}

}