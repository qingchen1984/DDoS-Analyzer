/**
 * 
 */
package com.database;

import java.sql.Timestamp;

/**
 * @author aavalos
 *
 */
public class RateContent {
	long time;
	int rate;
	
	/**
	 * Constructor
	 *
	 * @param time
	 * @param rate
	 */
	public RateContent(long time, int rate) {
		this.time = time;
		this.rate = rate;
	}

	/**
	 * Gets the value of time
	 *
	 * @return the time
	 */
	public long getTime() {
		return time;
	}
	/**
	 * Sets the value of time
	 *
	 * @param time the time to set
	 */
	public void setTime(long time) {
		this.time = time;
	}
	/**
	 * Gets the value of rate
	 *
	 * @return the rate
	 */
	public int getRate() {
		return rate;
	}
	/**
	 * Sets the value of rate
	 *
	 * @param rate the rate to set
	 */
	public void setRate(int rate) {
		this.rate = rate;
	}

}
