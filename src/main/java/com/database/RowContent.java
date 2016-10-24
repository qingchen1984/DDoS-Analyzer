package com.database;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class RowContent {
	private byte[] SrcAddress;
	private long numOfPackets;
	private long timeInSecs;
	
	RowContent(byte[] bs, long numOfPackets, long timeInSecs) {
		this.SrcAddress = bs;
		this.numOfPackets = numOfPackets;
		this.timeInSecs = timeInSecs;
	}
	
	public String getIpString() {
		String result = "";
		try {
			InetAddress ip = InetAddress.getByAddress(SrcAddress);
			result = ip.getHostAddress();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}
	
	public InetAddress getIp() {
		try {
			return InetAddress.getByAddress(SrcAddress);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public long getNumOfPackets() {
		return numOfPackets;
	}
	
	public long getTimeInSecs() {
		return timeInSecs;
	}
	
}
