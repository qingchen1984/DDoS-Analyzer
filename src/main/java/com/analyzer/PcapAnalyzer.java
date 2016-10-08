package com.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.database.DbStore;

public class PcapAnalyzer {
	
	private static String srcPcapFile = "C:\\Users\\aavalos\\Documents\\test500.pcap";
	private static int packetSize = 250000;

	public static void main(String[] args) {
		Logger logger = LogManager.getLogger();
		String dirName = System.getProperty("java.io.tmpdir") + "pcapTmp";
		long startTime = System.currentTimeMillis();
		//Clears DB from any previous results
		DbStore dbStrore = new DbStore(false, 0);
		dbStrore.clearDbTable();
		//Split pcap file
		PcapManager pm = new PcapManager();
		pm.pcapSplitter(srcPcapFile, dirName, packetSize);
		
		//Get the file from tmp dir
		File f = new File(dirName);
		File[] files = f.listFiles();
		
		//Parse each file in separate threads
		HashMap<Thread, PcapReader> threadArr = new HashMap<Thread, PcapReader>();
		for(File file: files){
			logger.info("File name: " + file.getName());
			PcapReader pr = new PcapReader(file.getAbsolutePath());
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
		iterator = threadArr.entrySet().iterator();
		while (iterator.hasNext()) {
			PcapReader pr = iterator.next().getValue();
			packetsProcessed = packetsProcessed + pr.getPacketsProcessed();
			packetsRead = packetsRead + pr.getPacketsRead();
		}
		
		logger.info("All threads completed in: " + (endTime - startTime)/1000 + " seconds");
		logger.info("Packets read: " + packetsRead);
		logger.info("Packets Processed: " + packetsProcessed);
		
		// Delete tmp directory
		try {
			FileUtils.deleteDirectory(new File(dirName));
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}
}
