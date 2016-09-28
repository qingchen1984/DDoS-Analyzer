package com.analyzer;

import java.io.EOFException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
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

  private static final int COUNT = 100000;

  private static final String PCAP_FILE_KEY
    = ReadPacketFile.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "src/main/resources/synack.pcap");

  private ReadPacketFile() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(PCAP_FILE);
    }
    Logger logger = LoggerFactory.getLogger(ReadPacketFile.class);
    DbStore dbStrore = new DbStore();
    long startTime = System.currentTimeMillis();
    for (int i = 1; i <= COUNT; i++) {
      try {
        Packet packet = handle.getNextPacketEx();
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet == null) { 
        	continue; 
        }
        
        IpV4Header header = ipV4Packet.getHeader();
        if (header.getProtocol().equals(IpNumber.TCP)) {
	        TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);
	        //System.out.println("Identification: " + header.getIdentification());
	        TcpHeader tcpHeader = tcpPacket.getHeader();
	        dbStrore.insertToDB(i, handle.getTimestamp(), 
	        		ByteBuffer.wrap(header.getSrcAddr().getAddress()).getLong(), 
	        		tcpHeader.getSrcPort().value(),
	        		ByteBuffer.wrap(header.getDstAddr().getAddress()).getLong(), 
	        		tcpHeader.getDstPort().value(), 
	        		header.getProtocol().hashCode(), tcpHeader.getAck(), tcpHeader.getSyn());
        } else if (header.getProtocol().equals(IpNumber.UDP)) {
        	UdpPacket udpPacket = ipV4Packet.get(UdpPacket.class);
        	UdpHeader udpHeader = udpPacket.getHeader();
	        dbStrore.insertToDB(i, handle.getTimestamp(), 
	        		ByteBuffer.wrap(header.getSrcAddr().getAddress()).getLong(), 
	        		udpHeader.getSrcPort().value(),
	        		ByteBuffer.wrap(header.getDstAddr().getAddress()).getLong(), 
	        		udpHeader.getDstPort().value(), 
	        		header.getProtocol().hashCode(), false, false);
        }
        
      } catch (TimeoutException | EOFException e) {
        System.out.println("EOF");
        break;
      }
    }
    long endTime = System.currentTimeMillis();
    logger.info("Total load time: " + (endTime - startTime)/1000 + " seconds");
    handle.close();
  }

}