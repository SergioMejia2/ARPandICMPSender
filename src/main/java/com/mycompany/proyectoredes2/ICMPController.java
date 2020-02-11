/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.proyectoredes2;

import Envio.Facade;
import static Envio.Facade.nif;
import java.net.InetAddress;
import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;

/**
 * FXML Controller class
 *
 * @author julia
 */
public class ICMPController implements Initializable {

    @FXML
    private Button btnIpOrigen;
    @FXML
    private Label lblBytes;
    @FXML
    private Label lblTamDato;
    @FXML
    private Label lblIpDestino;
    @FXML
    private TextField txtTamDato;
    @FXML
    private TextField txtIpDestino;
    @FXML
    private TextField txtIIpOrigen;
    @FXML
    private Button btnEnviar;
    @FXML
    private Label lblIpOrigen;
    @FXML
    private Label lblMensaje;
    @FXML
    private Label lblTitulo;

    private Facade controlador;
    private boolean seleccion;

    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        controlador = new Facade();
        seleccion = false;
    }

    @FXML
    private void OnClickIpOrigen(ActionEvent event) {
        if (this.seleccion == false) {
            this.seleccion = true;
            this.txtIIpOrigen.setEditable(false);
            List<PcapAddress> lista = nif.getAddresses();
            InetAddress origen = lista.get(1).getAddress();

            this.txtIIpOrigen.setText(origen.getHostAddress());
       
            //this.btnIpOrigen.s
            this.btnIpOrigen.setText("Usar Ip Manual");

        } else {
            this.seleccion = false;
            this.txtIIpOrigen.setEditable(true);
            this.txtIIpOrigen.clear();
            this.btnIpOrigen.setText("Usar Ip Nativa");
        }
    }

    @FXML
    private void OnClickEnviar(ActionEvent event) {
        try {
            if ((!this.txtIpDestino.getText().isEmpty())
                    && (!this.txtIIpOrigen.getText().isEmpty()) && (!this.txtTamDato.getText().isEmpty())) {
                String ipOrg = null;
                String ipDes = this.txtIpDestino.getText();
                if (!seleccion) {
                    ipOrg = this.txtIIpOrigen.getText();
                }
                int tam = Integer.parseInt(this.txtTamDato.getText());
                this.controlador.EnviarTramaICMP(ipDes, ipOrg, tam, seleccion);
                this.controlador.MostrarMensajeConfirmacion("Trama enviada Exitosamente.");
            } else {
                this.controlador.MostrarMensajeAdvertencia("Por favor complete los datos");
            }

        } catch (NotOpenException ex) {
            this.controlador.MostrarMensajeAdvertencia("Ocurrio un error, por favor vuelva a intentarlo.");
        } catch(NegativeArraySizeException e)
        {
            this.controlador.MostrarMensajeAdvertencia(e.getMessage());
        }
        catch(IllegalArgumentException ex)
        {
            this.controlador.MostrarMensajeAdvertencia(ex.getMessage());
        }
        catch (Exception ex) {
            this.controlador.MostrarMensajeAdvertencia("Ocurrio un error, por favor vuelva a intentarlo.");
        }
    }
}
