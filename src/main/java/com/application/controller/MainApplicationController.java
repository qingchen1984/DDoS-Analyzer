package com.application.controller;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.sql.Timestamp;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.analyzer.PcapAnalyzer;
import com.database.CountryContent;
import com.database.RateContent;
import com.database.RowContent;
import com.lynden.gmapsfx.GoogleMapView;
import com.lynden.gmapsfx.MapComponentInitializedListener;
import com.lynden.gmapsfx.javascript.object.GoogleMap;
import com.lynden.gmapsfx.javascript.object.LatLong;
import com.lynden.gmapsfx.javascript.object.MapOptions;
import com.lynden.gmapsfx.javascript.object.MapTypeIdEnum;
import com.lynden.gmapsfx.javascript.object.Marker;
import com.lynden.gmapsfx.javascript.object.MarkerOptions;
import com.vividsolutions.jts.geom.Coordinate;
import com.vividsolutions.jts.geom.Geometry;
import com.vividsolutions.jts.geom.GeometryFactory;
import com.vividsolutions.jts.geom.LineString;
import com.vividsolutions.jts.geom.impl.CoordinateArraySequence;
import com.vividsolutions.jts.simplify.DouglasPeuckerSimplifier;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Cursor;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.XYChart.Data;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.StackPane;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class MainApplicationController implements Initializable, MapComponentInitializedListener{
	
	@FXML private BorderPane mainBorderPane;
	@FXML private StackPane resultStack;
	@FXML private TableView<RowContent> floodTable;
	@FXML private TableColumn<RowContent, String> ipColumn;
	@FXML private TableColumn<RowContent, String> numOfPacketsColumn;
	@FXML private TableColumn<RowContent, String> attackTimeColumn;
	@FXML private TableColumn<RowContent, String> attackRateColumn;
	@FXML private TableColumn<RowContent, String> countryColumn;
	@FXML private TableColumn<RowContent, String> cityColumn;
	@FXML private GoogleMapView mapView;
	@FXML private LineChart<String, Number> lineChartView;
	@FXML private PieChart pieChartView;
	@FXML private ProgressBar progressBar;
	@FXML private Label progressLabel;
	@FXML private Label pieCaption;
	private GoogleMap map;
	private ObservableList<RowContent> tcpFloodData;
	private ObservableList<RowContent> udpFloodData;
	private ObservableList<RowContent> icmpFloodData;
	private ObservableList<PieChart.Data> tcpFloodCountryData;
	private ObservableList<PieChart.Data> udpFloodCountryData;
	private ObservableList<PieChart.Data> icmpFloodCountryData;
	private ObservableList<XYChart.Data<String, Number>> tcpAttackRate;
	private ObservableList<XYChart.Data<String, Number>> udpAttackRate;
	private ObservableList<XYChart.Data<String, Number>> icmpAttackRate;
	private HashMap<String, TableColumn<RowContent, String>> columnMap;
	private MapOptions mapOptions;
	private PcapAnalyzer pcapAnalyzer;
	private String dbName;
	private Logger logger;
	
	/**
	 * Opens the Preferences Dialog
	 * @param event
	 */
	public void openPreferences(ActionEvent event) {
		// Launch the Preferences window
		Parent root1;
		try {
			root1 = FXMLLoader.load(getClass().getResource("/com/application/view/Properties.fxml"));
			Stage newStage = new Stage();
			newStage.setScene(new Scene(root1, 300, 275));
			newStage.setTitle("Preferences");
			newStage.initModality(Modality.WINDOW_MODAL);
			newStage.initOwner(mainBorderPane.getScene().getWindow());
			newStage.showAndWait();
		} catch (IOException e) {
			logger.error("Error while opening preferences " + e.getMessage());
		}		
	}

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
		if(f == null) return;
		
		AtomicInteger progress = new AtomicInteger(0);
		AtomicReference<String> progressTitle = new AtomicReference<String>();
        startProgressIndicator(progressTitle, progress);
        
		Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
            	PcapAnalyzer pa = new PcapAnalyzer(f);
            	progress.set(0);
            	progressTitle.set("Splitting Pcap File...");
				pa.splitFile(progress);
				progress.set(0);
				progressTitle.set("Processing Pcap File...");
				pa.processFile(progress);
				pa.setStats();
				pa.cleanUp();
				return null;
            }
		};
		task.setOnSucceeded(e -> {
			//loadOverviewData(pcapAnalyzer);
			progress.set(-1);
			stopProgressIndicator();
        });
        Thread th = new Thread(task);
        th.setName("File Processor");
        th.start();
	}
	
	/**
	 * Opens history of processed data for user to make a selection.
	 * If user makes a selection, the results for it will be displayed.
	 * 
	 * @param event
	 */
	public void openPreviouslyProcessedData(ActionEvent event) {
		dbName = null;
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
			dbName = (String) newStage.getUserData();
		} catch (IOException e) {
			logger.error("Error while getting the window to display pre-processes files " + e.getMessage());
		}
		
		if(dbName == null) return;
		
		// Load data
		AtomicReference<String> progressTitle = new AtomicReference<String>();
		progressTitle.set("Processing information from database...");
		startProgressIndicator(progressTitle, null);
		
		Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
            	pcapAnalyzer = new PcapAnalyzer();
            	PropertiesData propData =  new PropertiesData();
    			pcapAnalyzer.loadProcessedData(
    					dbName, 
    					Integer.valueOf(propData.getProperty(PropertiesData.MINIMUM_PACKETS)),
    					Integer.valueOf(propData.getProperty(PropertiesData.MINIMUM_TIME)),
    					Integer.valueOf(propData.getProperty(PropertiesData.MINIMUM_RATE)));
    			propData.closeConnections();
    			
    			//Gets the data that will be used for the DOS attack table
    			tcpFloodData = FXCollections.observableArrayList(
    					pcapAnalyzer.getDosVictims(PcapAnalyzer.TCP_FLOODING_TABLE_NAME));
    			udpFloodData = FXCollections.observableArrayList(
    					pcapAnalyzer.getDosVictims(PcapAnalyzer.UDP_FLOODING_TABLE_NAME));
    			icmpFloodData = FXCollections.observableArrayList(
    					pcapAnalyzer.getDosVictims(PcapAnalyzer.ICMP_FLOODING_TABLE_NAME));

    			// Gets and formats the data that will be used for the overall attack rate line chart
    			tcpAttackRate = simplifyPlotPoints(
    					pcapAnalyzer.getAttackRate(PcapAnalyzer.TCP_FLOODING_TABLE_NAME));
    			udpAttackRate = simplifyPlotPoints(
    					pcapAnalyzer.getAttackRate(PcapAnalyzer.UDP_FLOODING_TABLE_NAME));
    			icmpAttackRate = simplifyPlotPoints(
    					pcapAnalyzer.getAttackRate(PcapAnalyzer.ICMP_FLOODING_TABLE_NAME));
    			
    			// Gets and formats the data that will be used for the country attacks pie chart
    			tcpFloodCountryData = getPieChartData(
    					pcapAnalyzer.getCountryVictims(PcapAnalyzer.TCP_FLOODING_TABLE_NAME));
    			udpFloodCountryData = getPieChartData(
    					pcapAnalyzer.getCountryVictims(PcapAnalyzer.UDP_FLOODING_TABLE_NAME));
    			icmpFloodCountryData = getPieChartData(
    					pcapAnalyzer.getCountryVictims(PcapAnalyzer.ICMP_FLOODING_TABLE_NAME));
    			
    			showOverviewData();
    			return null;
            }
        };
        
        task.setOnSucceeded(e -> {
			loadOverviewData(pcapAnalyzer);
			stopProgressIndicator();
        });
        Thread th = new Thread(task);
        th.setName("Saved File Processor");
        th.start();
	}

	/**
	 * Convert to a JavaFX-PlotChart-friendly array.
	 * 
	 * @param udppRate Original plot points to be converted.
	 * @return JavaFX-PlotChart-friendly array.
	 */
	private ObservableList<XYChart.Data<String, Number>> convertPlotPoints(ArrayList<RateContent> udppRate) {
		ObservableList<XYChart.Data<String, Number>> ol = FXCollections.observableArrayList();
		Iterator<RateContent> iUdp = udppRate.iterator();
		while (iUdp.hasNext()) {
			RateContent rc1 = iUdp.next();
			ol.add(new XYChart.Data<String, Number>((new Timestamp(rc1.getTime())).toString(), rc1.getRate()));
		}
		return ol;
	}

	/**
	 * Simplifies plot points using the Ramer–Douglas–Peucker algorithm.
	 * 
	 * @param tcpRate Original points to be simplified.
	 * @return Simplified JavaFX-PlotChart-friendly array.
	 */
	private ObservableList<Data<String, Number>>  simplifyPlotPoints(ArrayList<RateContent> plotPoints) {
		int size = plotPoints.size();
		if (size < 500) return convertPlotPoints(plotPoints);
		
		double distanceTolerance = size / 200;
		//logger.debug("Distance Tolerance to use: " + distanceTolerance);
		logger.debug("Original size of plot points: " +size);
		GeometryFactory gf= new GeometryFactory();
		// Convert plot points to an array of Coordinates
		Coordinate[] coordinates = new Coordinate[size];
		for (int i = 0; i < coordinates.length; i++) {
			RateContent rc = plotPoints.get(i);
			coordinates[i] = new Coordinate(rc.getTime(), rc.getRate());
		}
		Geometry geom = new LineString(new CoordinateArraySequence(coordinates), gf);
		// Simplify
		int count = 0;
		Geometry simplified = DouglasPeuckerSimplifier.simplify(geom, distanceTolerance);
		size = (int) simplified.getNumPoints();
		// Loop over the simplification trying to get a specific range varying the distance tolerance. 
		while ((size < 500 || size > 1500) && count < 5) {
			if (size < 500) {
				distanceTolerance = distanceTolerance / 2;
			} else if (size > 1500) {
				distanceTolerance = distanceTolerance * 2;
			}
			simplified = DouglasPeuckerSimplifier.simplify(geom, distanceTolerance);
			size = (int) simplified.getNumPoints();
			logger.debug("Iterim distance tolerance: " + distanceTolerance);
			logger.debug("Iterim size: " + size);
			count ++;
		}
		// Convert to a JavaFX-PlotChart-friendly array 
		List<Data<String, Number>> update = new ArrayList<Data<String, Number>>();
		for (Coordinate each : simplified.getCoordinates()) {
		    update.add(new Data<>((new Timestamp((long) each.x)).toString(), each.y));
		}
		logger.debug("Simplified size of plot points: " + update.size());
		return FXCollections.observableArrayList(update);
	}

	/**
	 * Fills up previously processed data on the overview pane
	 * 
	 * @param pcapAnalyzer
	 */
	private void loadOverviewData(PcapAnalyzer pcapAnalyzer) {
		((Label) mainBorderPane.lookup("#fileName")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_NAME)));
		String size = FileUtils.byteCountToDisplaySize((long) pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_SIZE));
		((Label) mainBorderPane.lookup("#fileSize")).setText(size);
		long millis = (long) pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_PROCESS_TIME);
		String timeFormatted = DurationFormatUtils.formatDuration(millis, "HH:mm:ss");
		((Label) mainBorderPane.lookup("#parseTime")).setText(timeFormatted);
		((Label) mainBorderPane.lookup("#packetsFound")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_PACKETS_READ)));
		((Label) mainBorderPane.lookup("#packetsIpV4")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_IPV4_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsIpV6")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_IPV6_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsTcp")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_TCP_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsUdp")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_UDP_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsIcmp")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_ICMP_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsUnknown")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_UNKNOWN_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsIllegal")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_ILLEGAL_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsProcessed")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_PACKETS_PROCESSED)));
		((Label) mainBorderPane.lookup("#packetsTcpFlood")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_TCP_FLOOD_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsUdpFlood")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_UDP_FLOOD_PACKETS)));
		((Label) mainBorderPane.lookup("#packetsIcmpFlood")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_ICMP_FLOOD_PACKETS)));
	}
	
	/**
	 * Displays the overview data
	 */
	public void showOverviewData() {
		showResultView("#overview_pane");
	}

	/**
	 * Displays the pane containing the TCP Flood table and populate its contents.
	 * 
	 * @param event
	 */
	public void showFloodTable(ActionEvent event) {
		Button srcButton = (Button) event.getSource();
		String id = srcButton.getId();
		if (id.contains("tcp")) {
			setUpFloodTable(PcapAnalyzer.TCP_FLOODING_TABLE_NAME, tcpFloodData);
		} else if (id.contains("udp")) {
			setUpFloodTable(PcapAnalyzer.UDP_FLOODING_TABLE_NAME, udpFloodData);
		} else if (id.contains("icmp")) {
			setUpFloodTable(PcapAnalyzer.ICMP_FLOODING_TABLE_NAME, icmpFloodData);
		} else {
			logger.error("Button id not recognized: " + id);
		}
	}

	/**
	 * Sets up the data previously processed on the flood table pane.
	 * 
	 * @param tableName Possible table names. See: PcapAnalyzer.*_FLOODING_TABLE_NAME
	 * @param data Table content.
	 */
	private void setUpFloodTable(String tableName, ObservableList<RowContent> data) {
		//Need to show pane first since "setCellValueFactory" needs it.
		String paneView = "#flood_table_pane";
		showResultView(paneView);
		// Setup the columns with the correct variable of RowContent
		columnMap.get(RowContent.SOURCE_ADDRESS).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.SOURCE_ADDRESS));
		columnMap.get(RowContent.NUMBER_OF_PACKETS).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.NUMBER_OF_PACKETS));
		columnMap.get(RowContent.ATTACK_TIME_IN_SECONDS).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.ATTACK_TIME_IN_SECONDS));
		columnMap.get(RowContent.ATTACK_RATE).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.ATTACK_RATE));
		columnMap.get(RowContent.COUNTRY_NAME).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.COUNTRY_NAME));
		columnMap.get(RowContent.CITY_NAME).setCellValueFactory(new PropertyValueFactory<RowContent, String>(RowContent.CITY_NAME));
		// Assigns 
		floodTable.setUserData(tableName);
		// Fill up the table
		floodTable.setItems(data);
	}
	
	/**
	 * Closes application
	 * 
	 * @param event
	 */
	public void closeApplication(ActionEvent event) {
		Platform.exit();
	}
	
	/**
	 * Sets all children of the result view to NOT visible.
	 */
	private void hideAllResultViews() {
		ObservableList<Node> list = resultStack.getChildren();
		Iterator<Node> iterator = list.iterator();
		while (iterator.hasNext()) {
			Node node = iterator.next();
			node.setVisible(false);
		}
	}
	
	/**
	 * Sets a specific child of the result view to visible.
	 * 
	 * @param id Id of Pane to be set visible.
	 */
	private void showResultView(String id) {
		hideAllResultViews();
		resultStack.lookup(id).setVisible(true);
	}
	
	/**
	 * Shows the pane containing the loaded map
	 * 
	 * @param event
	 */
	public void showMap(ActionEvent event) {
		Button srcButton = (Button) event.getSource();
		String id = srcButton.getId();
		if (id.contains("tcp")) {
			setUpMap(tcpFloodData);
		} else if (id.contains("udp")) {
			setUpMap(udpFloodData);
		} else if (id.contains("icmp")) {
			setUpMap(icmpFloodData);
		} else {
			logger.error("Button id not recognized: " + id);
		}
		showResultView("#map_pane");
	}
	
	/**
	 * Shows the pane containing the loaded line chart
	 * 
	 * @param event
	 */
	public void showDosRate(ActionEvent event) {
		setLineChartData(null, null, null);
		showResultView("#line_chart_pane");
	}
	
	/**
	 * Shows the pane containing the loaded country pie chart.
	 * 
	 * @param event
	 */
	public void showCountryPieChart(ActionEvent event) {
		String id = ((Button) event.getSource()).getId();
		// Set chart data depending on button pressed
		if(id.equals("tcp_flood_pie_chart_button")) {
			pieChartView.setTitle("Countries affected by amount of TCP packets");
			pieChartView.setData(tcpFloodCountryData);
		} else if(id.equals("udp_flood_pie_chart_button")) {
			pieChartView.setTitle("Countries affected by amount of UDP packets");
			pieChartView.setData(udpFloodCountryData);
		} else if(id.equals("icmp_flood_pie_chart_button")) {
			pieChartView.setTitle("Countries affected by amount of ICMP packets");
			pieChartView.setData(icmpFloodCountryData);
		} else {
			// source button not recognized
			logger.error("Button id not recognized: " + id);
			return;
		}
		
		// Change the title in case that the chart is empty
		if (pieChartView.getData() == null || pieChartView.getData().size() == 0) {
			pieChartView.setTitle("No content in Chart");
		} 
		
		// Adds mouse events for each pie slice.
		for (final PieChart.Data data : pieChartView.getData()) {
		    data.getNode().setOnMousePressed(e -> {
		    	pieCaption.setVisible(true);
		    	pieCaption.setLayoutX(e.getSceneY());
		    	pieCaption.setLayoutY(e.getSceneY());
		    	String formattedNumber = NumberFormat.getIntegerInstance().format((int) data.getPieValue());
		    	pieCaption.setText(formattedNumber + " packets");
		    });
		    data.getNode().setOnMouseEntered(e -> {
		    	pieChartView.getScene().setCursor(Cursor.HAND);
		    });
		    data.getNode().setOnMouseExited(e -> {
		    	pieChartView.getScene().setCursor(Cursor.DEFAULT);
		    	pieCaption.setVisible(false);
		    });
		}

		showResultView("#pie_chart_pane");
	}
	
	/**
	 * Gets the data that will be displayed in the affected countries pie chart.
	 * 
	 * @param countryData list containing countries and packets affected.
	 * @return data processed to be used in a pie chart.
	 */
	private ObservableList<PieChart.Data> getPieChartData(ArrayList<CountryContent> countryData) {
		ObservableList<PieChart.Data> response = FXCollections.observableArrayList();
		Iterator<CountryContent> i = countryData.iterator();
		while(i.hasNext()) {
			CountryContent content = i.next();
			response.add(new PieChart.Data(content.getCountry(), content.getPacketCount()));
		}
	    return response;
	}

	/**
	 * Loads the line chart containing the attack rate over time.
	 * 
	 * @param address Address where to obtain the attack trend from. If null, then all addresses/DOS-attack-types
	 * @param addressString Ip address of displayed data. Used only when address != null
	 * @param tableName Table name where to obtain the data from. Used only when address != null
	 */
	private void setLineChartData(byte[] address, String addressString,  String tableName) {
		ObservableList<XYChart.Series<String, Number>> series = FXCollections.observableArrayList();
		if (address == null) {
			// Uses data from all affected addresses
			series.add(new XYChart.Series<>("TCP rate", tcpAttackRate));
			series.add(new XYChart.Series<>("UDP rate", udpAttackRate));
			series.add(new XYChart.Series<>("ICMP rate", icmpAttackRate));
		} else {
			// Uses data for a specific address
			ArrayList<RateContent> attackList = pcapAnalyzer.getAttackRateForAddress(tableName, address);
			series.add(new XYChart.Series<>(addressString + " rate", simplifyPlotPoints(attackList)));
		}
		lineChartView.setCreateSymbols(false);
		lineChartView.setAnimated(false);
		lineChartView.setData(series);
		showResultView("#line_chart_pane");
	}

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		// Initialize map
		mapView.addMapInializedListener(this);
		
		hideAllResultViews();
		
		// Initialize table
		columnMap = new HashMap<String, TableColumn<RowContent, String>>();
		columnMap.put(RowContent.SOURCE_ADDRESS, ipColumn);
		columnMap.put(RowContent.NUMBER_OF_PACKETS, numOfPacketsColumn);
		columnMap.put(RowContent.ATTACK_TIME_IN_SECONDS, attackTimeColumn);
		columnMap.put(RowContent.ATTACK_RATE, attackRateColumn);
		columnMap.put(RowContent.COUNTRY_NAME, countryColumn);
		columnMap.put(RowContent.CITY_NAME, cityColumn);
		
		// Set click events for table to open a line chart
		floodTable.getSelectionModel().selectedItemProperty().addListener((observableValue, oldValue, newValue) -> {
			byte[] address = observableValue.getValue().getSrcAddressArr();
			String addressString = observableValue.getValue().getSrcAddress();
			String tableName = (String) floodTable.getUserData();
			setLineChartData(address, addressString, tableName);
		});
		
		// Set mouse over events to rows with data to show user they can be clicked
		floodTable.setRowFactory( tv -> {
			TableRow<RowContent> row = new TableRow<>();
			// change mouse to a hand pointer
			row.setOnMouseEntered(mouseEvent -> {
				if (!row.isEmpty()) tv.getScene().setCursor(Cursor.HAND);
			});
			// change black to the default on row exit
			row.setOnMouseExited(mouseEvent -> {
				tv.getScene().setCursor(Cursor.DEFAULT);
			}); 
			return row;
		});

		// Initialize LineChart
		tcpAttackRate = FXCollections.observableArrayList();
		udpAttackRate = FXCollections.observableArrayList();
		icmpAttackRate = FXCollections.observableArrayList();
		//Initialize PieChart
		tcpFloodCountryData = FXCollections.observableArrayList();
		udpFloodCountryData = FXCollections.observableArrayList();
		icmpFloodCountryData = FXCollections.observableArrayList();
		
		//logger.debug("Completed the Program initialization");
		 
	}

	/* (non-Javadoc)
	 * @see com.lynden.gmapsfx.MapComponentInitializedListener#mapInitialized()
	 */
	@Override
	public void mapInitialized() {
		// For some reason the logger has to be initialized after the map was initialized
		logger = LogManager.getLogger();
		
		 //Set the initial properties of the map.
		mapOptions = new MapOptions();
	    mapOptions.center(new LatLong(0, 0))
	    		.mapType(MapTypeIdEnum.ROADMAP)
	            .overviewMapControl(false)
	            .panControl(false)
	            .rotateControl(false)
	            .scaleControl(false)
	            .streetViewControl(false)
	            .zoomControl(false)
	            .zoom(1);
	}

	/**
	 * Sets up and displays map containing markers for each item in the ObservableList
	 * 
	 * @param data List of RowContent containing the information for the markers.
	 */
	private void setUpMap(ObservableList<RowContent> data) {
		map = mapView.createMap(mapOptions);
		if (data == null) return;
		Iterator<RowContent> iterator = data.iterator();
		RowContent rc;
		while (iterator.hasNext()) {
			rc = iterator.next();
			double latt = rc.getLatitude();
			double longt =  rc.getLongitude();
			// Skip if data is empty
			if (latt == 0 && longt == 0) continue;  
			LatLong latLong = new LatLong(latt,longt);
			//Add marker to the map
			String attackDuration = DurationFormatUtils.formatDuration(rc.getTimeInSecs()*1000, "HH:mm:ss");
			MarkerOptions markerOptions = new MarkerOptions();
			markerOptions.position(latLong);
			markerOptions.title("IP: " + rc.getSrcAddress() + "\n"
							+ "Country: " + rc.getCountry() + "\n"
							+ "City: " + rc.getCity() + "\n"
							+ "Packets: " + rc.getNumOfPackets() + "\n"
							+ "Attack duration: " + attackDuration + "\n"
							+ "Attack rate: " + rc.getAttackRate() + " packets/second \n");
			Marker marker = new Marker(markerOptions);
			map.addMarker( marker );
		}
		
	}
	
	/**
	 * Starts indicators for long tasks
	 */
	private void startProgressIndicator(AtomicReference<String> progressTitle, AtomicInteger progress) {
		mainBorderPane.getScene().setCursor(Cursor.WAIT);
		if (progress == null){
			progressLabel.setText(progressTitle.get());
			progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
		} else { 
			Task<Void> task = new Task<Void>() {
			    @Override public Void call() {
			    	// Delaying the start of the thread
			    	try {
						Thread.sleep(1000);
					} catch (Exception e) {
						logger.error("Error while sleeping" + e.getMessage());
					}
			    	int value = 0;
			    	String message = "";
			    	while (value >= 0) { // exits when we feed -1
			    		try {
							Thread.sleep(1000);
						} catch (Exception e) {
							logger.error("Error while sleeping" + e.getMessage());
						}
			    		int newVal = progress.get();
			    		String newMessage = progressTitle.get();
			    		if (!message.equals(newMessage)) {
			    			message = newMessage;
			    			updateMessage(message);
			    		}
			    		if (value != newVal) {
			    			value = newVal;
			    			updateProgress(value, 100);
			    		}
			    	}
			        return null;
			    }
			};
			progressBar.progressProperty().bind(task.progressProperty());
			progressLabel.textProperty().bind(task.messageProperty());
			Thread th = new Thread(task);
			th.setName("Progress Inspector");
			th.start();
		}
	}
	
	/**
	 * Stops indicators for long tasks
	 */
	private void stopProgressIndicator() {
		mainBorderPane.getScene().setCursor(Cursor.DEFAULT);
		progressBar.progressProperty().unbind();
		progressLabel.textProperty().unbind();
		progressBar.setProgress(0);
		progressLabel.setText("");
	}
}
