package com.application.controller;

import java.io.File;

import com.analyzer.PcapAnalyzer;

import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainApplicationController {

	public void openFile() {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open Resource File");
		
		fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PCAP", "*.pcap")
            );
		
		File f = fileChooser.showOpenDialog(new Stage());
		PcapAnalyzer pcapAnalyzer = new PcapAnalyzer();
		System.out.println(pcapAnalyzer.isInDB(f));
	}
}
