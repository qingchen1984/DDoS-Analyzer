package com.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

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
		
		//Parse each file
		ArrayList<Thread> threadArr = new ArrayList<Thread>();
		for(File file: files){
			System.out.println(file.getName());
			Thread th = new Thread(new PcapReader(file.getAbsolutePath()));
			th.setName(file.getName());
			th.start();
			threadArr.add(th);
		}
		Iterator<Thread> iterator = threadArr.iterator();
		try {
			while (iterator.hasNext()) {
				iterator.next().join();
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		long endTime = System.currentTimeMillis();
		System.out.println("All threads completed in: " + (endTime - startTime)/1000 + " seconds");
        
		// Delete tmp directory
		try {
			FileUtils.deleteDirectory(new File(dirName));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
