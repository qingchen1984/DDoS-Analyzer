package com.application.view;
	
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Locale;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;


public class Main extends Application {
	private static String OS = null;
	public static void main(String[] args) {
		ClassLoader cl = ClassLoader.getSystemClassLoader();
        URL[] urls = ((URLClassLoader)cl).getURLs();

        for(URL url: urls){
        	String systemClass = url.getFile();
        	if ((isWindows() && systemClass.endsWith("jnetpcap.dll"))
        			|| (isUnix() && systemClass.endsWith("libjnetpcap.so")) ) {
        		try {
        			System.load(systemClass);
        			break;
        		} catch (Exception e) {
        			System.out.println("Error found while loading jnetpcap.dll");
        			e.printStackTrace();
        		}
        	}
        	
        }
		
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("MainApplication.fxml"));
        primaryStage.setTitle("Darknet PCAP Analyzer");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();
        primaryStage.setOnCloseRequest(e -> {
        	System.out.println("Closing program. Good bye!");
        	Platform.exit();
        	System.exit(0);
        });

    }
    
    public static String getOsName()  {
       if(OS == null) { OS = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH); }
       return OS;
    }
    
    public static boolean isWindows() {
       return getOsName().indexOf("win") >= 0;
    }

    public static boolean isUnix() {
    	return getOsName().indexOf("nux") >= 0;
    }
}
