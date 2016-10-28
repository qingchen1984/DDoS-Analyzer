package com.application.controller;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import com.analyzer.PcapAnalyzer;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.MenuItem;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class MainApplicationController {
	
	@FXML
	BorderPane mainBorderPane;
	
	/**
	 * Opens dialog for users to select a PCAP file to be processed.
	 * 
	 * @param event
	 */
	public void openFile(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open Resource File");
		
		fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PCAP", "*.pcap")
            );
		Stage fileStage = new Stage();
		fileStage.initModality(Modality.WINDOW_MODAL);
		fileStage.initOwner(mainBorderPane.getScene().getWindow());
		File f = fileChooser.showOpenDialog(fileStage);
		PcapAnalyzer pcapAnalyzer = new PcapAnalyzer();
		System.out.println(pcapAnalyzer.isInDb(f));
	}
	
	/**
	 * Opens history of processed data for user to make a selection.
	 * If user makes a selection, the results for it will be displayed.
	 * 
	 * @param event
	 */
	public void openPreviouslyProcessedData(ActionEvent event) {
		try {
			// Launch the File History view
			Parent root1  = FXMLLoader.load(getClass().getResource("/com/application/view/DatabaseNames.fxml"));
			Stage newStage = new Stage();
			newStage.setScene(new Scene(root1, 300, 275));
			newStage.setTitle("File History");
			newStage.initModality(Modality.WINDOW_MODAL);
			newStage.initOwner(mainBorderPane.getScene().getWindow());
			newStage.showAndWait();
			
			// Get selection if any
			newStage.getUserData();
			String selection = (String) newStage.getUserData();
			if(selection != null) {
				// TODO: Process selection
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Closes application
	 * 
	 * @param event
	 */
	public void closeApplication(ActionEvent event) {
		Platform.exit();
	}
}
