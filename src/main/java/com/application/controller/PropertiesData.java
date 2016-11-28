/**
 * 
 */
package com.application.controller;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

/**
 * @author  aavalos
 */
public class PropertiesData {
	private Properties prop;
	private InputStream input = null;
	private OutputStream output = null;
	private String fileLocation = "config.properties";
	public static final String MINIMUM_PACKETS = "minimumPackets";
	public static final String MINIMUM_TIME = "minimumTime";
	public static final String MINIMUM_RATE = "minimumRate";

	/**
	 * Constructor
	 *
	 */
	public PropertiesData() {
		prop = new Properties();
		try {
			//
			input = this.getClass().getClassLoader().getResourceAsStream(fileLocation);
			// load a properties file
			prop.load(input);
			//prop..getClass().
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Sets property value
	 * 
	 * @param propName
	 * @param propValue
	 */
	public void setProperty(String propName, String propValue) {
		prop.replace(propName, propValue);
	}
	
	/**
	 * Saves property value(s)
	 * 
	 * @return
	 */
	public boolean saveProperties() {
		try {
			output = new FileOutputStream(fileLocation);
			prop.store(output, null);
		} catch (IOException e) {
			return false;
		}
		return true;
	}
	
	/**
	 * Gets property value
	 * 
	 * @param propName
	 */
	public String getProperty(String propName) {
		try {
			prop.load(input);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return prop.getProperty(propName);
	}
	
	/**
	 * Close connections
	 */
	public void closeConnections() {
		if (input != null) {
			try {
				input.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if (output != null) {
			try {
				output.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}