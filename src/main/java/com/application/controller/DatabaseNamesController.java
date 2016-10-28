package com.application.controller;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import com.analyzer.PcapAnalyzer;

import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.stage.Stage;

public class DatabaseNamesController implements Initializable {
	@FXML
    private ListView<String> listView;
	@FXML
    private Button selectButton;
	@FXML
    private Button cancelButton;
	
	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		PcapAnalyzer pcapAnalyzer = new PcapAnalyzer();
		//load with name of pre-processed files
		List<String> values = Arrays.asList(pcapAnalyzer.getDbNames());
        listView.setItems(FXCollections.observableList(values));
	}
	
	/**
	 * Selects item highlighted in the list view.
	 * 
	 * @param event
	 */
	public void makeSelection(ActionEvent event) {
		String selection = listView.getSelectionModel().getSelectedItem();
		Node source = (Node) event.getSource();
		Stage stage = (Stage) source.getScene().getWindow();
		stage.setUserData(selection);
	    stage.close();
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
