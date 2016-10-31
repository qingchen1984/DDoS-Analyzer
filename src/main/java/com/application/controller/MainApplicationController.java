package com.application.controller;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.ResourceBundle;

import org.apache.commons.io.FileUtils;

import com.analyzer.PcapAnalyzer;
import com.database.RowContent;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class MainApplicationController implements Initializable {
	
	@FXML private BorderPane mainBorderPane;
	@FXML private StackPane resultStack;
	@FXML private TableView<RowContent> tcpFloodTable;
	@FXML private TableView<RowContent> udpFloodTable;
	@FXML private TableView<RowContent> icmpFloodTable;
	@FXML private TableColumn<RowContent, String> ipColumnTcp;
	@FXML private TableColumn<RowContent, String> numOfPacketsColumnTcp;
	@FXML private TableColumn<RowContent, String> attackTimeColumnTcp;
	@FXML private TableColumn<RowContent, String> attackRateColumnTcp;
	@FXML private TableColumn<RowContent, String> countryColumnTcp;
	@FXML private TableColumn<RowContent, String> cityColumnTcp;
	@FXML private TableColumn<RowContent, String> ipColumnUdp;
	@FXML private TableColumn<RowContent, String> numOfPacketsColumnUdp;
	@FXML private TableColumn<RowContent, String> attackTimeColumnUdp;
	@FXML private TableColumn<RowContent, String> attackRateColumnUdp;
	@FXML private TableColumn<RowContent, String> countryColumnUdp;
	@FXML private TableColumn<RowContent, String> cityColumnUdp;
	@FXML private TableColumn<RowContent, String> ipColumnIcmp;
	@FXML private TableColumn<RowContent, String> numOfPacketsColumnIcmp;
	@FXML private TableColumn<RowContent, String> attackTimeColumnIcmp;
	@FXML private TableColumn<RowContent, String> attackRateColumnIcmp;
	@FXML private TableColumn<RowContent, String> countryColumnIcmp;
	@FXML private TableColumn<RowContent, String> cityColumnIcmp;
	private ObservableList<RowContent> tcpFloodData;
	private ObservableList<RowContent> udpFloodData;
	private ObservableList<RowContent> icmpFloodData;
	
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
		PcapAnalyzer pa = new PcapAnalyzer();
		pa.processPcapFile(f);
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
			String dbName = (String) newStage.getUserData();
			
			// Load data
			if(dbName != null) {
				PcapAnalyzer pcapAnalyzer = new PcapAnalyzer();
				pcapAnalyzer.loadProcessedData(dbName);
				
				ArrayList<RowContent> tcpVictims = pcapAnalyzer.getDosVictims(PcapAnalyzer.TCP_FLOODING_TABLE_NAME);
				tcpFloodData = FXCollections.observableArrayList(tcpVictims);
				
				ArrayList<RowContent> udpVictims = pcapAnalyzer.getDosVictims(PcapAnalyzer.UDP_FLOODING_TABLE_NAME);
				udpFloodData = FXCollections.observableArrayList(udpVictims);
				
				ArrayList<RowContent> icmpVictims = pcapAnalyzer.getDosVictims(PcapAnalyzer.ICMP_FLOODING_TABLE_NAME);
				icmpFloodData = FXCollections.observableArrayList(icmpVictims);
				
				loadOverviewData(pcapAnalyzer);
				showOverviewData();
				//showTcpFloodTable();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	private void loadOverviewData(PcapAnalyzer pcapAnalyzer) {
		((Label) mainBorderPane.lookup("#fileName")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_NAME)));
		String size = FileUtils.byteCountToDisplaySize((long) pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_SIZE));
		((Label) mainBorderPane.lookup("#fileSize")).setText(size);
		long millis = (long) pcapAnalyzer.getStatisticss(PcapAnalyzer.FILE_PROCESS_TIME);
		Date date = new Date(millis);
		DateFormat formatter = new SimpleDateFormat("HH:mm:ss");
		String timeFormatted = formatter.format(date); 
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
		((Label) mainBorderPane.lookup("#packetsIcmpFlood")).setText(String.valueOf(pcapAnalyzer.getStatisticss(PcapAnalyzer.TOTAL_ICMP_PACKETS)));
	}
	
	public void showOverviewData() {
		showResultView("#overview_pane");
	}

	public void showTcpFloodTable(ActionEvent event) {
		//Need to show pane first since "setCellValueFactory" needs it.
		showResultView("#tcp_flood_table_pane");
		
		ipColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("srcAddress"));
		numOfPacketsColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("numOfPackets"));
		attackTimeColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("timeInSecs"));
		attackRateColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("attackRate"));
		countryColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("country"));
		cityColumnTcp.setCellValueFactory(new PropertyValueFactory<RowContent, String>("city"));
		// Fill up the table
		tcpFloodTable.setItems(tcpFloodData);
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

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		hideAllResultViews();
	}
}
