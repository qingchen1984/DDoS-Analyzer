package com.database;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Class containing information regarding DOS attack
 * 
 * @author aavalos
 *
 */
public class RowContent {
	private String srcAddress;
	private long numOfPackets;
	private long timeInSecs;
	private long attackRate;
	private String country;
	private String city;
	
	/**
	 * Constructor
	 * 
	 * @param srcAddress Source address of attack
	 * @param numOfPackets Number of attack packets associated with srcAddress
	 * @param timeInSecs Time of attack associated with srcAddress
	 * @param country Country of srcAddress
	 * @param city City of srcAddress
	 */
	RowContent(String srcAddress, long numOfPackets, long timeInSecs, String country, String city) {
		this.srcAddress = srcAddress;
		this.numOfPackets = numOfPackets;
		this.timeInSecs = timeInSecs;
		this.country = country;
		this.city = city;
		if (timeInSecs > 0 ) {
			attackRate = numOfPackets / timeInSecs;
		} else {
			attackRate = numOfPackets;
		}
		
	}

	/**
	 * Gets the value of srcAddress
	 *
	 * @return the srcAddress
	 */
	public String getSrcAddress() {
		return srcAddress;
	}

	/**
	 * Sets the value of srcAddress
	 *
	 * @param srcAddress the srcAddress to set
	 */
	public void setSrcAddress(String srcAddress) {
		this.srcAddress = srcAddress;
	}

	/**
	 * Gets the value of numOfPackets
	 *
	 * @return the numOfPackets
	 */
	public long getNumOfPackets() {
		return numOfPackets;
	}

	/**
	 * Sets the value of numOfPackets
	 *
	 * @param numOfPackets the numOfPackets to set
	 */
	public void setNumOfPackets(long numOfPackets) {
		this.numOfPackets = numOfPackets;
	}

	/**
	 * Gets the value of timeInSecs
	 *
	 * @return the timeInSecs
	 */
	public long getTimeInSecs() {
		return timeInSecs;
	}

	/**
	 * Sets the value of timeInSecs
	 *
	 * @param timeInSecs the timeInSecs to set
	 */
	public void setTimeInSecs(long timeInSecs) {
		this.timeInSecs = timeInSecs;
	}

	/**
	 * Gets the value of attackRate
	 *
	 * @return the attackRate
	 */
	public long getAttackRate() {
		return attackRate;
	}

	/**
	 * Sets the value of attackRate
	 *
	 * @param attackRate the attackRate to set
	 */
	public void setAttackRate(long attackRate) {
		this.attackRate = attackRate;
	}

	/**
	 * Gets the value of country
	 *
	 * @return the country
	 */
	public String getCountry() {
		return country;
	}

	/**
	 * Sets the value of country
	 *
	 * @param country the country to set
	 */
	public void setCountry(String country) {
		this.country = country;
	}

	/**
	 * Gets the value of city
	 *
	 * @return the city
	 */
	public String getCity() {
		return city;
	}

	/**
	 * Sets the value of city
	 *
	 * @param city the city to set
	 */
	public void setCity(String city) {
		this.city = city;
	}
}
