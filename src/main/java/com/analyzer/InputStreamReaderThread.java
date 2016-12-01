package com.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicInteger;

public class InputStreamReaderThread implements Runnable {
	
	private InputStream inputStream;
	private final AtomicInteger progress;
	private int localProgress = 0;

	public InputStreamReaderThread(InputStream is, AtomicInteger progress) {
		inputStream = is;
		this.progress = progress;
	}

	@Override
	public void run() {
		while (localProgress < 100) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				printFromInputStream(inputStream);
			} catch (Exception e) {
				break;
			}
		}
	}

	// convert InputStream to String
	private void printFromInputStream(InputStream is) throws Exception {

		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(is));
			char[] chArr = new char[4];
			while ((br.read(chArr)) != -1) {
				StringBuilder sb = new StringBuilder();
				//checks for single digit percentages like 0-9%
				if (chArr[1] == '%' 
						&& Character.isDigit(chArr[0])) { 
					sb.append(chArr[0]);
				} 
				//checks for double digit percentages like 10-99%
				else if (chArr[2] == '%' 
						&& Character.isDigit(chArr[0]) 
						&& Character.isDigit(chArr[1])) {
					sb.append(chArr[0]);
					sb.append(chArr[1]);
				}
				//checks for triple digit percentages like 100%
				else if (chArr[3] == '%' 
						&& Character.isDigit(chArr[0]) 
						&& Character.isDigit(chArr[1])  
						&& Character.isDigit(chArr[2])) {
					sb.append(chArr[0]);
					sb.append(chArr[1]);
					sb.append(chArr[2]);
				}
				if (sb.length() > 0) {
					updateProgress(Integer.valueOf(sb.toString()));
				}
			}
		} catch (IOException e) {
			throw new Exception();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	/**
	 * Updates splitting progress if there is a new value.
	 * 
	 * @param update new value
	 */
	private synchronized void updateProgress(int update) {
		if (localProgress != update) {
			localProgress = update;
			progress.set(localProgress);
		}
	}

}
