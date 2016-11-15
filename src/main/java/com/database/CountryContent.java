/**
 * 
 */
package com.database;

/**
 * @author aavalos
 *
 */
public class CountryContent {
	private String country;
	private int packetCount;
	private int totalSeconds;
	
	
	/**
	 * Constructor
	 *
	 * @param country
	 * @param packetCount
	 * @param totalSeconds
	 */
	public CountryContent(String country, int packetCount, int totalSeconds) {
		super();
		this.country = country;
		this.packetCount = packetCount;
		this.totalSeconds = totalSeconds;
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
	 * Gets the value of packetCount
	 *
	 * @return the packetCount
	 */
	public int getPacketCount() {
		return packetCount;
	}


	/**
	 * Sets the value of packetCount
	 *
	 * @param packetCount the packetCount to set
	 */
	public void setPacketCount(int packetCount) {
		this.packetCount = packetCount;
	}


	/**
	 * Gets the value of totalSeconds
	 *
	 * @return the totalSeconds
	 */
	public int getTotalSeconds() {
		return totalSeconds;
	}


	/**
	 * Sets the value of totalSeconds
	 *
	 * @param totalSeconds the totalSeconds to set
	 */
	public void setTotalSeconds(int totalSeconds) {
		this.totalSeconds = totalSeconds;
	}
	
}
