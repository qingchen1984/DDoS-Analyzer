package com.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.database.CountryContent;
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
	private HashMap<String,ArrayList<CountryContent>> countryStatistics = new HashMap<String,ArrayList<CountryContent>>();
	private static final int PACKET_COUNT_MAX = 5000000; //5000000 ; 10000000
	private Logger logger;
	private DbStore dbStore;
	private boolean splitFile;
	private String tmpDirName;
	private File[] files;
	private String databaseName;
	private File originalfile;
	private long processTimeInMillis;
	private HashMap<Thread, PcapReader> threadArr;
	
	public PcapAnalyzer(File originalfile) {
		this();
		this.originalfile = originalfile;
		databaseName = parseDbName(originalfile);
		dbStore = new DbStore(databaseName, true);
		threadArr = new HashMap<Thread, PcapReader>();
		tmpDirName = System.getProperty("java.io.tmpdir") + "pcapTmp";
		processTimeInMillis = 0;
		files = new File[1];
		files[0] = originalfile;
		if (originalfile.length() > 1 * 1024 * 1024 * 1024) {
			splitFile = true;
	    } else {
	    	splitFile = true;
	    }
	}
	
	public PcapAnalyzer() {
		logger = LogManager.getLogger();
		dbStore = null;
	}
	
	/**
	 * Checks if file was already parsed in the DB.
	 * 
	 * @param file File to be checked
	 * @return true if file has been found parser, false otherwise.
	 */
	public static boolean isInDb(File file) {
		String fileName = file.getName();
		DbStore db = new DbStore("",false);
		String[] dbNames = db.getAllDataBaseNames();
		for (String storedDB : dbNames) {
			if (fileName.equals(storedDB)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Gets the file name that were previously processes in the database.
	 * 
	 * @return
	 */
	public static String[] getDbNames() {
		DbStore db = new DbStore("",false);
		return db.getAllDataBaseNames();
	}
	
	public void processPcapFile() {

		//splitFile(originalfile);
		
		//processFile();

		setStats();
		
		cleanUp();
	}

	/**
	 * Removes temporary files created
	 */
	public void cleanUp() {
		// Delete tmp directory
		try {
			FileUtils.deleteDirectory(new File(tmpDirName));
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Gets statistics from the file processing threads and saves it to the database.
	 * 
	 * @param originalfile
	 * @param startTime
	 * @param endTime
	 */
	public void setStats() {
		Iterator<Entry<Thread, PcapReader>> iterator;
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
				processTimeInMillis, infoPackets);
		
		logger.info("All threads completed in: " + processTimeInMillis/1000 + " seconds");
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
	}

	/**
	 * Process files and stores into databases
	 */
	public void processFile(AtomicInteger progress) {
		ArrayList<AtomicInteger> progressArr = new ArrayList<AtomicInteger>();
		long startTime = System.currentTimeMillis();
		for(File file: files){
			logger.info("File name: " + file.getName());
			AtomicInteger threadProgress = new AtomicInteger(0);
			PcapReader pr = new PcapReader(file.getAbsolutePath(), databaseName, threadProgress, PACKET_COUNT_MAX);
			Thread th = new Thread(pr);
			th.setName(file.getName());
			th.start();
			threadArr.put(th, pr);
			progressArr.add(threadProgress);
		}
		
		//Create thread to compiles the progress from all processing threads into a single one
		int arraySize = progressArr.size();
		Runnable reader = new Runnable() {
			private int current = 0;
			@Override
			public void run() {
				while (current < 100) {
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					double overallProgress = 0.0;
					for (AtomicInteger threadProgress : progressArr) {
						double individualVal = (double) threadProgress.get(); // 0-100
						individualVal = individualVal/100.0; // 0-1.0
						overallProgress = overallProgress + individualVal; //up to arrSize
					}
					int newVal = (int) (overallProgress / arraySize * 100); //0-100
					if (newVal != current) {
						current = newVal;
						progress.set(current);
					}
				}
			}
		};
		Thread th1 = new Thread(reader);
        th1.setName("Overall Progress watcher");
        th1.start();
        
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
		processTimeInMillis = processTimeInMillis + (endTime - startTime);
		progress.set(100); // if we haven't done so, set it to completed.
	}

	/**
	 * Splits files to be processed if needed.
	 * 
	 * @param originalfile
	 */
	public void splitFile(AtomicInteger progress) {
		long startTime = System.currentTimeMillis();
		if (splitFile) {
			// Split pcap file
			PcapManager pm = new PcapManager(progress);
			pm.pcapSplitter(originalfile.getPath(), tmpDirName, PACKET_COUNT_MAX);
			
			// Get the files from tmp dir
			File f = new File(tmpDirName);
			files = f.listFiles();
		}
		long endTime = System.currentTimeMillis();
		processTimeInMillis = processTimeInMillis + (endTime - startTime);
	}
	
	/**
	 * Processes data from database and stores them in memory.
	 * Use getStatisticss, getDosVictims, getAttackRate to retrieve it.
	 * 
	 * @param dbName file name that was used to store into database
	 * @param minPacket
	 * @param minSecs
	 * @param rate
	 */
	public void loadProcessedData(String dbName, int minPacket, int minSecs, int rate) {
		
		dbStore = new DbStore(parseDbName(new File(dbName)), false);
		// Load statistics
		dbStore.getSummaryTable(statistics);
		
		dosStatistics.put(TCP_FLOODING_TABLE_NAME, 
				dbStore.getDosVictims(DbStore.TCP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		dosStatistics.put(UDP_FLOODING_TABLE_NAME, 
				dbStore.getDosVictims(DbStore.UDP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		dosStatistics.put(ICMP_FLOODING_TABLE_NAME, 
				dbStore.getDosVictims(DbStore.ICMP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		
		rateStatistics.put(TCP_FLOODING_TABLE_NAME, 
				dbStore.getAttackRate(DbStore.TCP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		rateStatistics.put(UDP_FLOODING_TABLE_NAME, 
				dbStore.getAttackRate(DbStore.UDP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		rateStatistics.put(ICMP_FLOODING_TABLE_NAME, 
				dbStore.getAttackRate(DbStore.ICMP_FLOODING_TABLE_NAME, minPacket, minSecs, rate));
		
		countryStatistics.put(TCP_FLOODING_TABLE_NAME, 
				dbStore.getCountryVictims(DbStore.TCP_FLOODING_TABLE_NAME));
		countryStatistics.put(UDP_FLOODING_TABLE_NAME, 
				dbStore.getCountryVictims(DbStore.UDP_FLOODING_TABLE_NAME));
		countryStatistics.put(ICMP_FLOODING_TABLE_NAME, 
				dbStore.getCountryVictims(DbStore.ICMP_FLOODING_TABLE_NAME));
	}
	
	/**
	 * Gets general statistics previously processed by loadProcessedData.
	 * 
	 * @param key
	 * @return
	 */
	public Object getStatisticss(String key) {
		return statistics.get(key);
	}
	
	/**
	 * Gets DOS statistics previously processed by loadProcessedData.
	 * 
	 * @param key
	 * @return
	 */
	public ArrayList<RowContent> getDosVictims(String key) {
		return dosStatistics.get(key);
	}
	
	/**
	 * Gets country victims previously processed by loadProcessedData.
	 * 
	 * @param key
	 * @return
	 */
	public ArrayList<CountryContent> getCountryVictims(String key) {
		return countryStatistics.get(key);
	}
	
	/**
	 * Gets overall attack rate previously processed by loadProcessedData.
	 * 
	 * @param key
	 * @return
	 */
	public ArrayList<RateContent> getAttackRate(String key) {
		return rateStatistics.get(key);
	}
	
	/**
	 * 
	 * @param tableName
	 * @param address
	 * @return
	 */
	public ArrayList<RateContent> getAttackRateForAddress(String tableName, byte[] address) {
		if (dbStore == null) return null;
		return dbStore.getAttackRate(tableName, address);
	}

	/**
	 * Gets the database name given a file
	 * 
	 * @param file File to get the name from
	 * @return File containing the name
	 */
	private String parseDbName(File file) {
		String databaseName = file.getName();
		databaseName = databaseName.replace(".",  "_");
		return databaseName;
	}
}
