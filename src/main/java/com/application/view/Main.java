package com.application.view;
	
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;


public class Main extends Application {
	public static void main(String[] args) {
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
