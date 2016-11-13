package com.analyzer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class that holds function to manage a Pcap file.
 * 
 * @author aavalos
 *
 */
public class PcapManager {
	private static Logger logger;
	private AtomicInteger progress;
	
	public PcapManager(AtomicInteger progress) {
		this.progress = progress;
	}
	
	/**
	 * Splits pcap file into fixed-sized packets.
	 * 
	 * @param srcFile - Source pcap file to be split.
	 * @param outputDir - Directory where the processed files will be saved.
	 * @param numOfPackets - Number of packets 
	 * @return The exit value of the split subprocess. By convention, the value 0 indicates normal termination.
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public int pcapSplitter(String srcFile, String outputDir, int numOfPackets ) {
		logger = LogManager.getLogger();
		int result = -1; //failure by default
		String[] cmd = { 
				"lib/SplitCap_2-1/SplitCap.exe", 
				"-r", srcFile,
				"-o", outputDir,
				"-s", "packets", String.valueOf(numOfPackets) };
		
		//Create temporary directory
		logger.info("Creating directory under: " + outputDir);
		File f = new File(outputDir);
		if (!f.exists()) {
			f.mkdirs();
		}
		
		//Start SplitCap.exe to get file split
		logger.info("Splitting files.");
		Process p;
		try {
			p = Runtime.getRuntime().exec(cmd);
		} catch (IOException e) {
			return result;
		}
		
		//Read the progress output
		InputStream is = p.getInputStream();
		InputStreamReaderThread iSReader = new InputStreamReaderThread(is, progress);
		//iSReader.run();
		
		Thread th = new Thread(iSReader);
		th.setName("Split Progress Reader");
		th.start();
		try {
			result = p.waitFor();
		} catch (InterruptedException e) {
			return result;
		}
		progress.set(100); // Setting the progress to 100% since it completed
		logger.info("Splitting completed into " + f.list().length + " files.");
		return result;
	}
}