package com.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.database.DbStore;
import com.database.RateContent;
import com.database.RowContent;

public class PcapAnalyzer {
	
	//private static String srcPcapFile = "C:\\Users\\aavalos\\Downloads\\dataset.pcap";
	//private static String srcPcapFile = "C:\\Temp\\dataset.pcap.Packets_0.pcap";
	//private static String srcPcapFile = "C:\\Users\\aavalos\\Documents\\test500.pcap";
	public static final String TCP_FLOODING_TABLE_NAME = DbStore.TCP_FLOODING_TABLE_NAME;
	public static final String UDP_FLOODING_TABLE_NAME = DbStore.UDP_FLOODING_TABLE_NAME;
	public static final String ICMP_FLOODING_TABLE_NAME = DbStore.ICMP_FLOODING_TABLE_NAME;
	public static final String TOTAL_PACKETS_READ = DbStore.TOTAL_PACKETS_READ;
	public static final String TOTAL_PACKETS_PROCESSED = DbStore.TOTAL_PACKETS_PROCESSED;
	public static final String TOTAL_IPV4_PACKETS = DbStore.TOTAL_IPV4_PACKETS;
	public static final String TOTAL_IPV6_PACKETS = DbStore.TOTAL_IPV6_PACKETS;
	public static final String TOTAL_TCP_PACKETS = DbStore.TOTAL_TCP_PACKETS;
	public static final String TOTAL_UDP_PACKETS = DbStore.TOTAL_UDP_PACKETS;
	public static final String TOTAL_ICMP_PACKETS = DbStore.TOTAL_ICMP_PACKETS;
	public static final String TOTAL_UNKNOWN_PACKETS = DbStore.TOTAL_UNKNOWN_PACKETS;
	public static final String TOTAL_ILLEGAL_PACKETS = DbStore.TOTAL_ILLEGAL_PACKETS;
	public static final String TOTAL_TCP_FLOOD_PACKETS = DbStore.TOTAL_TCP_FLOOD_PACKETS;
	public static final String TOTAL_UDP_FLOOD_PACKETS = DbStore.TOTAL_UDP_FLOOD_PACKETS;
	public static final String TOTAL_ICMP_FLOOD_PACKETS = DbStore.TOTAL_ICMP_FLOOD_PACKETS;
	public static final String FILE_NAME = DbStore.FILE_NAME;
	public static final String FILE_SIZE = DbStore.FILE_SIZE;
	public static final String FILE_PROCESS_TIME = DbStore.FILE_PROCESS_TIME;
	private HashMap<String,Object> statistics = new HashMap<String,Object>();
	private HashMap<String,ArrayList<RateContent>> rateStatistics = new HashMap<String,ArrayList<RateContent>>();
	private HashMap<String,ArrayList<RowContent>> dosStatistics = new HashMap<String,ArrayList<RowContent>>();
	private static int packetSize = 5000000;
	private Logger logger;
	
	public PcapAnalyzer() {
		logger = LogManager.getLogger();
	}
/*
	public static void main(String[] args) {
		
	}
	*/
	
	/**
	 * Checks if file was already parsed in the DB.
	 * 
	 * @param file File to be checked
	 * @return true if file has been found parser, false otherwise.
	 */
	public boolean isInDb(File file) {
		String databaseName = parseDbName(file);
		DbStore db = new DbStore("",false);
		String[] dbNames = db.getAllDataBaseNames();
		for (String storedDB : dbNames) {
			if (databaseName.equals(storedDB)) {
				return true;
			}
		}
		return false;
	}
	
	public String[] getDbNames() {
		DbStore db = new DbStore("",false);
		return db.getAllDataBaseNames();
	}
	
	public void processPcapFile(File originalfile) {
		
		String dirName = System.getProperty("java.io.tmpdir") + "pcapTmp";
		boolean splitFile = false;
		
		// Calculate if file needs feeding depending on size.
		File[] files = null;
		if (originalfile.length() > 1 * 1024 * 1024 * 1024) {
			splitFile = true;
		}
		
		// Create DB
		String databaseName = parseDbName(originalfile);
		DbStore dbStore = new DbStore(databaseName, true);
		
		long startTime = System.currentTimeMillis();
		
		if (splitFile) {
			// Split pcap file
			PcapManager pm = new PcapManager();
			pm.pcapSplitter(originalfile.getPath(), dirName, packetSize);
			
			// Get the file from tmp dir
			File f = new File(dirName);
			files = f.listFiles();
		} else {
			files = new File[1];
			files[0] = originalfile;
		}
		
		// Parse each file in separate threads
		HashMap<Thread, PcapReader> threadArr = new HashMap<Thread, PcapReader>();
		for(File file: files){
			logger.info("File name: " + file.getName());
			PcapReader pr = new PcapReader(file.getAbsolutePath(), databaseName);
			Thread th = new Thread(pr);
			th.setName(file.getName());
			th.start();
			threadArr.put(th,  pr);
		}
		
		// Wait until every thread finishes
		Iterator<Entry<Thread, PcapReader>> iterator = threadArr.entrySet().iterator();
		try {
			while (iterator.hasNext()) {
				iterator.next().getKey().join();
			}
		} catch (InterruptedException e) {
			logger.error(e.getMessage());
		}
		long endTime = System.currentTimeMillis();
		
		// Get statistics
		long packetsProcessed = 0;
		long packetsRead = 0;
		long ipV4PacketsRead = 0;
		long ipV6PacketsRead = 0;
		long tcpPacketsRead = 0;
		long udpPacketsRead = 0;
		long icmpPacketsRead = 0;
		long unknownPacketsRead = 0;
		long illegalPacketsRead = 0;
		long tcpFloodPacketsRead = 0;
		long udpFloodPacketsRead = 0;
		long icmpFloodPacketsRead = 0;
		iterator = threadArr.entrySet().iterator();
		while (iterator.hasNext()) {
			PcapReader pr = iterator.next().getValue();
			packetsProcessed = packetsProcessed + pr.getPacketsProcessed();
			packetsRead = packetsRead + pr.getPacketsRead();
			ipV4PacketsRead = ipV4PacketsRead + pr.getIpV4pPacketsRead();
			ipV6PacketsRead = ipV6PacketsRead + pr.getIpV6pPacketsRead();
			tcpPacketsRead = tcpPacketsRead + pr.getTcpPacketsRead();
			udpPacketsRead = udpPacketsRead + pr.getUdpPacketsRead();
			icmpPacketsRead = icmpPacketsRead + pr.getIcmpPacketsRead();
			unknownPacketsRead = unknownPacketsRead + pr.getUnknownPacketsRead();
			illegalPacketsRead = illegalPacketsRead + pr.getIllegalPacketsRead();
			tcpFloodPacketsRead = tcpFloodPacketsRead + pr.getTcpFloodPacketsRead();
			udpFloodPacketsRead = udpFloodPacketsRead + pr.getUdpFloodPacketsRead();
			icmpFloodPacketsRead = icmpFloodPacketsRead + pr.getIcmpFloodPacketsRead();
		}
		HashMap<String,Long> infoPackets = new HashMap<String,Long>();
		infoPackets.put("packetsTotal", packetsRead);
		infoPackets.put("packetsProcessed", packetsProcessed);
		infoPackets.put("packetsIpV4", ipV4PacketsRead);
		infoPackets.put("packetsIpV6", ipV6PacketsRead);
		infoPackets.put("packetsTcp", tcpPacketsRead);
		infoPackets.put("packetsUdp", udpPacketsRead);
		infoPackets.put("packetsIcmp", icmpPacketsRead);
		infoPackets.put("packetsUnknown", unknownPacketsRead);
		infoPackets.put("packetsIllegal", illegalPacketsRead);
		infoPackets.put("packetsTcpFlood",tcpFloodPacketsRead);
		infoPackets.put("packetsUdpFlood",udpFloodPacketsRead);
		infoPackets.put("packetsIcmpFlood", icmpFloodPacketsRead);
		
		// Save statistics 
		dbStore.setSummaryTable(originalfile.getName(), originalfile.length(), 
				(endTime - startTime), infoPackets);
		
		logger.info("All threads completed in: " + (endTime - startTime)/1000 + " seconds");
		logger.info("Packets read: " + packetsRead);
		logger.info("Packets Processed: " + packetsProcessed);
		logger.info("TCP packets Read: " + tcpPacketsRead);
		logger.info("UDP packets Read: " + udpPacketsRead);
		logger.info("ICMP packets Read: " + icmpPacketsRead);
		logger.info("Unknwon packets Read: " + unknownPacketsRead);
		logger.info("Illegal packets Read: " + illegalPacketsRead);
		logger.info("TCP Flood packets Read: " + tcpFloodPacketsRead);
		logger.info("UDP Flood packets Read: " + udpFloodPacketsRead);
		logger.info("ICMP Flood packets Read: " + icmpFloodPacketsRead);
		
		// Delete tmp directory
		try {
			FileUtils.deleteDirectory(new File(dirName));
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
		
		
		
	}
	
	public void loadProcessedData(String dbName) {
		DbStore dbStore = new DbStore(dbName, false);
		// Load statistics
		dbStore.getSummaryTable(statistics);
		
		dosStatistics.put(TCP_FLOODING_TABLE_NAME, dbStore.getDosVictims(DbStore.TCP_FLOODING_TABLE_NAME));
		dosStatistics.put(UDP_FLOODING_TABLE_NAME, dbStore.getDosVictims(DbStore.UDP_FLOODING_TABLE_NAME));
		dosStatistics.put(ICMP_FLOODING_TABLE_NAME, dbStore.getDosVictims(DbStore.ICMP_FLOODING_TABLE_NAME));
		
		rateStatistics.put(TCP_FLOODING_TABLE_NAME, dbStore.getAttackRate(DbStore.TCP_FLOODING_TABLE_NAME));
		rateStatistics.put(UDP_FLOODING_TABLE_NAME, dbStore.getAttackRate(DbStore.UDP_FLOODING_TABLE_NAME));
		rateStatistics.put(ICMP_FLOODING_TABLE_NAME, dbStore.getAttackRate(DbStore.ICMP_FLOODING_TABLE_NAME));
		
	}
	
	/**
	 * 
	 * @param key
	 * @return
	 */
	public Object getStatisticss(String key) {
		return statistics.get(key);
	}
	
	/**
	 * 
	 * @param key
	 * @return
	 */
	public ArrayList<RowContent> getDosVictims(String key) {
		return dosStatistics.get(key);
	}
	
	/**
	 * 
	 * @param key
	 * @return
	 */
	public ArrayList<RateContent> getAttackRate(String key) {
		return rateStatistics.get(key);
	}

	/**
	 * Gets the database name given a file
	 * 
	 * @param file File to get the name from
	 * @return File containing the name
	 */
	private String parseDbName(File file) {
		String databaseName = file.getName();
		databaseName = databaseName.substring(0, databaseName.indexOf("."));
		return databaseName;
	}
}
