package com.analyzer;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
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
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;
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

	private String pcapFile;

	PcapReader(String pcapFileLocation) {
		logger = LogManager.getLogger(PcapReader.class);
		pcapFile = pcapFileLocation;
		packetIndex = 0;
		packetProcessed = 0;
	}
	
	public int getPacketsRead() {
		return packetIndex;
	}
	
	public int getPacketsProcessed() {
		return packetProcessed;
	}

	@Override
	public void run() {
		DbStore dbStrore;
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
		
		dbStrore = new DbStore(false, 0);

		Map<Short, List<IpV4Packet>> ipV4Fragments = new HashMap<Short, List<IpV4Packet>>();

		long startTime = System.currentTimeMillis();
		for (;;) {
			try {
				IpV4Packet ipV4Packet = handle.getNextPacketEx().get(IpV4Packet.class);
				packetIndex++;
				if (ipV4Packet == null) {
					continue;
				}

				IpV4Header header = ipV4Packet.getHeader();
				Timestamp tstmp = handle.getTimestamp();
				byte[] srcAddress = header.getSrcAddr().getAddress();
				byte[] destAddress = header.getDstAddr().getAddress();
				int protocol = header.getProtocol().hashCode();
				int srcPort = -1;
				int destPort = -1;
				boolean ack = false;
				boolean syn = false;

				if (protocol == TCP) {
					TcpHeader tcpHeader = ipV4Packet.get(TcpPacket.class).getHeader();
					ack = tcpHeader.getAck();
					syn = tcpHeader.getSyn();
					srcPort = tcpHeader.getSrcPort().valueAsInt();
					destPort = tcpHeader.getDstPort().valueAsInt();
				} else if (protocol == ICMPV4 || protocol == UDP) {
					UdpPacket udpPacket = ipV4Packet.get(UdpPacket.class);
					if (udpPacket != null) {
						UdpHeader udpHeader = udpPacket.getHeader();
						srcPort = udpHeader.getSrcPort().valueAsInt();
						destPort = udpHeader.getDstPort().valueAsInt();
					} else {// likely a fragment
						short id = header.getIdentification();
						FragmentedPacket fragmentedPacket = ipV4Packet.get(FragmentedPacket.class);
						if (fragmentedPacket != null) {
							if (ipV4Fragments.containsKey(id)) {// add fragment to list
								ipV4Fragments.get(id).add(ipV4Packet);
							} else {// start a new fragmented list
								List<IpV4Packet> list = new ArrayList<IpV4Packet>();
								list.add(ipV4Packet.get(IpV4Packet.class));
								ipV4Fragments.put(id, list);
							}
							if (!header.getMoreFragmentFlag()) {
								IpV4Packet ipDefragPack = IpV4Helper.defragment(ipV4Fragments.get(id));
								UdpPacket udpDefragPacket = ipDefragPack.get(UdpPacket.class);
								if (udpDefragPacket != null) {
									UdpHeader udpHeader = udpDefragPacket.getHeader();
									srcPort = udpHeader.getSrcPort().valueAsInt();
									destPort = udpHeader.getDstPort().valueAsInt();
									ipV4Fragments.remove(id);
								} else {
									logger.warn("Could not defragment UDP packet " + packetIndex);
								}
							}
						} else {
							logger.warn("Packet not fragmented but does not have UDP class " + packetIndex);
						}

					}
				} else {
					logger.warn("IP Protocol not recognized: " + header.getProtocol().toString() + " #" + packetIndex);
				}

				// add row to DB batch
				packetProcessed++;

				dbStrore.addToBatch(packetProcessed, tstmp, srcAddress, srcPort, destAddress, destPort, protocol, ack,
						syn);

				if (packetProcessed % 100000 == 0) {
					dbStrore.commitBatch();
				}

			} catch (EOFException e) {
				logger.info("EOF");
				break;
			} catch (PcapNativeException | NotOpenException | TimeoutException e) {
				logger.error(e.getLocalizedMessage());
			}
		} // end of for loop

		// inserts any remainder rows in batch to the DB
		dbStrore.commitBatch();
		long endTime = System.currentTimeMillis();
		logger.debug("Total load time: " + (endTime - startTime) / 1000 + " seconds");
		logger.debug("Packets read: " + packetIndex);
		logger.debug("Packets proccessed: " + packetProcessed);
		handle.close();
	}

}