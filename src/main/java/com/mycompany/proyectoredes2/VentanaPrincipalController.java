/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.proyectoredes2;

import Envio.Facade;
import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.stage.Stage;
import org.pcap4j.util.NifSelector;

/**
 * FXML Controller class
 *
 * @author julia
 */
public class VentanaPrincipalController implements Initializable {

    @FXML
    private Button btnICMP;
    @FXML
    private Button btnARP;
    @FXML
    private Label lblTitulo;

    private Stage ARP;
    private Stage ICMP;
    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb)
    {    
        try
        { 
        Facade.nif = new NifSelector().selectNetworkInterface();
        }
        catch (Exception e)
        {
            Alert alert = new Alert(Alert.AlertType.ERROR, e.getMessage(), ButtonType.OK);
        alert.showAndWait();

        if (alert.getResult() == ButtonType.OK) {
            alert.close();
        }
        }
    }    

    @FXML
    private void OnClickICMP(ActionEvent event) {
        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/ICMP.fxml"));
        Parent root = null;

        try {
            root = loader.load();
        } catch (IOException ex) {
            Logger.getLogger(VentanaPrincipalController.class.getName()).log(Level.SEVERE, null, ex);
        }
        ICMP = new Stage();
        ICMP.setTitle("ARP");
        ICMP.setScene(new Scene(root));
        ICMPController controlador = loader.getController();
        //controlador.setMan(this.man);
        ICMP.show();
    }

    @FXML
    private void OnClickARP(ActionEvent event) {
        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("/fxml/ARP.fxml"));
        Parent root = null;

        try {
            root = loader.load();
        } catch (IOException ex) {
            Logger.getLogger(VentanaPrincipalController.class.getName()).log(Level.SEVERE, null, ex);
        }
        ARP = new Stage();
        ARP.setTitle("ARP");
        ARP.setScene(new Scene(root));
        ARPController controlador = loader.getController();
        //controlador.setMan(this.man);
        ARP.show();
    }
    
}
