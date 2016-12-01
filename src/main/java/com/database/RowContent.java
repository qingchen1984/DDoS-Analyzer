package com.database;

/**
 * Class containing information regarding DOS attack
 * 
 * @author aavalos
 *
 */
public class RowContent {
	public static final String SOURCE_ADDRESS = "srcAddress";
	public static final String NUMBER_OF_PACKETS = "numOfPackets";
	public static final String ATTACK_TIME_IN_SECONDS = "timeInSecs";
	public static final String ATTACK_RATE = "attackRate";
	public static final String COUNTRY_NAME = "country";
	public static final String CITY_NAME = "city";
	private String srcAddress;
	private byte[] srcAddressArr;
	private long numOfPackets;
	private long timeInSecs;
	private long attackRate;
	private String country;
	private String city;
	private double latitude;
	private double longitude;
	
	/**
	 * Constructor
	 * 
	 * @param srcAddress Source address of attack
	 * @param srcByteArr Source address 
	 * @param numOfPackets Number of attack packets associated with srcAddress
	 * @param timeInSecs Time of attack associated with srcAddress
	 * @param country Country of srcAddress
	 * @param city City of srcAddress
	 */
	RowContent(byte[] srcByteArr, String srcAddress, long numOfPackets, long timeInSecs, long attackRate,
			String country, String city, double latitude, double longitude) {
		this.srcAddressArr = srcByteArr;
		this.srcAddress = srcAddress;
		this.numOfPackets = numOfPackets;
		this.timeInSecs = timeInSecs;
		this.country = country;
		this.city = city;
		this.attackRate = attackRate;
		this.latitude = latitude;
		this.longitude = longitude;
	}
	
	RowContent(String country, int numOfCountries, int packetCount, int totalSeconds) {
		this.country = country;
		
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

	/**
	 * Gets the value of latitude
	 *
	 * @return the latitude
	 */
	public double getLatitude() {
		return latitude;
	}

	/**
	 * Sets the value of latitude
	 *
	 * @param latitude the latitude to set
	 */
	public void setLatitude(double latitude) {
		this.latitude = latitude;
	}

	/**
	 * Gets the value of longitude
	 *
	 * @return the longitude
	 */
	public double getLongitude() {
		return longitude;
	}

	/**
	 * Sets the value of longitude
	 *
	 * @param longitude the longitude to set
	 */
	public void setLongitude(double longitude) {
		this.longitude = longitude;
	}

	/**
	 * Gets the value of srcAddressArr
	 *
	 * @return the srcAddressArr
	 */
	public byte[] getSrcAddressArr() {
		return srcAddressArr;
	}

	/**
	 * Sets the value of srcAddressArr
	 *
	 * @param srcAddressArr the srcAddressArr to set
	 */
	public void setSrcAddressArr(byte[] srcAddressArr) {
		this.srcAddressArr = srcAddressArr;
	}
	
	
}
