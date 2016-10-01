package com.analyzer;

import java.io.EOFException;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.util.PcapPacketSupport;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Packet.Builder;
import org.pcap4j.packet.Packet.Header;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.database.DbStore;

@SuppressWarnings("javadoc")
public class ReadPacketFile {
	private static Logger logger;
	private static DbStore dbStrore;
	
	private final static int TCP = IpNumber.TCP.hashCode();
	private final static int ICMPV4 = IpNumber.ICMPV4.hashCode();
	private final static int UDP = IpNumber.UDP.hashCode();
  
	private static final String PCAP_FILE_KEY 
	= ReadPacketFile.class.getName() + ".pcapFile";
	private static final String PCAP_FILE 
	= System.getProperty(PCAP_FILE_KEY, "src/main/resources/test500.pcap");

  private ReadPacketFile() {
	  
  }

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(PCAP_FILE);
    }
    
    logger = LoggerFactory.getLogger(ReadPacketFile.class);
	dbStrore = new DbStore(false, 0);
	dbStrore.clearDbTable();
    
    int packetProcessed = 0;
    int packetIndex = 0;
    
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
	    	} else {//likely a fragment
	    		
	    		if (protocol == IpNumber.ICMPV4.hashCode()) {
	    			System.out.println("ICMPV4 packet found with no UDP header. Packet: " + packetIndex);
	    		}
	    		if (ipV4Packet.getHeader().getMoreFragmentFlag()) {
	    			System.out.println("Fragmented packet " + packetIndex);
	    		} else {
	    			System.out.println("Packet not fragmented but does not have UDP class " + packetIndex);
	    		}
	    	}
	    } else {
    		System.out.println("IP Protocol not recognized: " + header.getProtocol().toString() + " #" + packetIndex);
        }
        
        //add row to DB batch
        packetProcessed++;
        dbStrore.insertToDB(packetProcessed, tstmp, 
        		srcAddress, 
        		srcPort,
        		destAddress, 
        		destPort, 
        		protocol, 
        		ack, syn);
        
        if (packetProcessed % 50000 == 0) {
        	dbStrore.commitBatch();
        	//dbStrore = new DbStore(false, 0);
        }
        if (packetProcessed == 450000) {
        	int x=0;
        	x = 2;
        }
        
        
        
      } catch (TimeoutException | EOFException e) {
        System.out.println("EOF");
        break;
      }
    } //end of for loop
    
    //inserts any remainder rows in batch to the DB
    dbStrore.commitBatch();
    long endTime = System.currentTimeMillis();
    logger.info("Total load time: " + (endTime - startTime)/1000 + " seconds");
    logger.info("Packets read: " + packetIndex);
    logger.info("Packets proccessed: " + packetProcessed);
    handle.close();
  }

}