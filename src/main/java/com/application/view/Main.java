package com.application.view;
	
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;


public class Main extends Application {
	public static void main(String[] args) {
		Logger logger = LogManager.getLogger(Main.class);
		String nativeDll = Main.class.getClassLoader().getResource("jnetpcapNative/jnetpcap.dll").getPath();
		try {
			//System.load(nativeDll);
		} catch (Exception e) {
			logger.fatal("Unable to load the following library" + nativeDll, e );
			return;
		}
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("MainApplication.fxml"));
        primaryStage.setTitle("Darknet PCAP Analyzer");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();
    }
}
