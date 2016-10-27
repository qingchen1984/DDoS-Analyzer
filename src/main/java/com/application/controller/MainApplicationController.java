package com.application.controller;

import java.io.File;

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
		System.out.println(f.getName() + f.length());
	}
}
