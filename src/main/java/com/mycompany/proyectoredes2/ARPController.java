/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.proyectoredes2;

import Envio.Facade;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import org.pcap4j.core.NotOpenException;

/**
 * FXML Controller class
 *
 * @author julia
 */
public class ARPController implements Initializable {

    @FXML
    private Label lblMensaje;
    @FXML
    private Label lblMensajeIP;
    @FXML
    private Button btnEnviar;
    @FXML
    private TextField txtIpDestino;
    @FXML
    private Label lblTitulo;

    private Facade controlador;
    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        controlador = new Facade();
    }    

    @FXML
    private void OnClickEnviar(ActionEvent event) {
        try {
             if (!this.txtIpDestino.getText().isEmpty()) {
                String ipDes = this.txtIpDestino.getText();
                this.controlador.EnviarTramaARP(ipDes);
                if(Envio.EnvioARP.resolvedAddr != null)
                    this.controlador.MostrarMensajeConfirmacion("MAC Hallada: "+Envio.EnvioARP.resolvedAddr);
                else throw new NotOpenException();
            } else {
                this.controlador.MostrarMensajeAdvertencia("Por favor complete los datos");
            }
        }catch (NotOpenException ex){
            this.controlador.MostrarMensajeAdvertencia("Ocurrio un error, por favor vuelva a intentarlo.");
        } 
        catch (Exception ex) {
            this.controlador.MostrarMensajeAdvertencia(ex.getMessage());
        }
    }
    public Facade getControlador() {
        return controlador;
    }

    public void setControlador(Facade controlador) {
        this.controlador = controlador;
    }
}
