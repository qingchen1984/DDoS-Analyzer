/**
 * 
 */
package com.application.controller;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Properties;
import java.util.ResourceBundle;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

/**
 * @author aavalos
 *
 */
public class PropertiesController implements Initializable {
	@FXML
	private TextField packets;
	@FXML
	private TextField time;
	@FXML
	private TextField rate;

	/* (non-Javadoc)
	 * @see javafx.fxml.Initializable#initialize(java.net.URL, java.util.ResourceBundle)
	 */
	@Override
	public void initialize(URL location, ResourceBundle resources) {
		Properties prop = new Properties();
		InputStream input = null;

		try {

			input = new FileInputStream("src/main/resources/config.properties");

			// load a properties file
			prop.load(input);

			// get the property value and display it
			packets.setText(prop.getProperty("minimumPackets"));
			time.setText(prop.getProperty("minimumTime"));
			rate.setText(prop.getProperty("minimumRate"));

		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
	}
	
	/**
	 * Saves the information entered in the text fields then closes the window
	 * 
	 * @param event
	 */
	public void saveInfo(ActionEvent event) {
		Properties prop = new Properties();
		OutputStream output = null;

		try {

			output = new FileOutputStream("src/main/resources/config.properties");

			// set the properties value
			prop.setProperty("minimumPackets", packets.getText());
			prop.setProperty("minimumTime", time.getText());
			prop.setProperty("minimumRate", rate.getText());

			// save properties to project root folder
			prop.store(output, null);

		} catch (IOException io) {
			io.printStackTrace();
		} finally {
			if (output != null) {
				try {
					output.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}
		closeWindow(event);
	}
	
	/**
	 * Closes dialog.
	 * 
	 * @param event
	 */
	public void closeWindow(ActionEvent event) {
		Node source = (Node) event.getSource();
		Stage stage = (Stage) source.getScene().getWindow();
	    stage.close();
	}

}
