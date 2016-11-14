/**
 * 
 */
package com.application.controller;

import java.net.URL;
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
	public TextField packets;
	@FXML
	public TextField time;
	@FXML
	public TextField rate;
	private PropertiesData propData;

	/* (non-Javadoc)
	 * @see javafx.fxml.Initializable#initialize(java.net.URL, java.util.ResourceBundle)
	 */
	@Override
	public void initialize(URL location, ResourceBundle resources) {
		propData = new PropertiesData();
		// get the property value and display it
		packets.setText(propData.getProperty(PropertiesData.MINIMUM_PACKETS));
		time.setText(propData.getProperty(PropertiesData.MINIMUM_TIME));
		rate.setText(propData.getProperty(PropertiesData.MINIMUM_RATE));
	}
	
	/**
	 * Saves the information entered in the text fields then closes the window
	 * 
	 * @param event
	 */
	public void saveInfo(ActionEvent event) {
		// set the properties value
		propData.setProperty(PropertiesData.MINIMUM_PACKETS, packets.getText());
		propData.setProperty(PropertiesData.MINIMUM_TIME, time.getText());
		propData.setProperty(PropertiesData.MINIMUM_RATE, rate.getText());

		// save properties 
		propData.saveProperties();
		
		closeWindow(event);
	}
	
	/**
	 * Closes dialog.
	 * 
	 * @param event
	 */
	public void closeWindow(ActionEvent event) {
		propData.closeConnections();
		Node source = (Node) event.getSource();
		Stage stage = (Stage) source.getScene().getWindow();
	    stage.close();
	}

}
