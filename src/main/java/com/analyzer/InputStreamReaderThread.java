package com.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class InputStreamReaderThread implements Runnable {
	InputStream inputStream;

	InputStreamReaderThread(InputStream is) {
		inputStream = is;
	}

	@Override
	public void run() {
		for (;;) {
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
	private static void printFromInputStream(InputStream is) throws Exception {

		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(is));
			char[] chArr = new char[4];
			while ((br.read(chArr)) != -1) {
				StringBuilder sb = new StringBuilder();
				if (chArr[1] == '%' && Character.isDigit(chArr[0])) {
					sb.append(chArr[0]);
				} else if (chArr[2] == '%' && Character.isDigit(chArr[0]) && Character.isDigit(chArr[1])) {
					sb.append(chArr[0]);
					sb.append(chArr[1]);
				} else if (chArr[2] == '%' && Character.isDigit(chArr[0]) && Character.isDigit(chArr[1])) {
					sb.append(chArr[0]);
					sb.append(chArr[1]);
				}
				if (sb.length() > 0) {
					System.out.print(sb);
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

}
