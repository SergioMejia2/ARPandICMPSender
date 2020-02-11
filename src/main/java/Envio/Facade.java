/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Envio;

import java.net.InetAddress;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import org.pcap4j.core.PcapNetworkInterface;

/**
 *
 * @author julia
 */
public class Facade {
    
    public static PcapNetworkInterface nif;

    public void MostrarMensajeAdvertencia(String mensaje) {
        Alert alert = new Alert(Alert.AlertType.ERROR, mensaje, ButtonType.OK);
        alert.showAndWait();

        if (alert.getResult() == ButtonType.OK) {
            alert.close();
        }
    }

    public void MostrarMensajeConfirmacion(String mensaje) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION, mensaje, ButtonType.OK);
        alert.showAndWait();

        if (alert.getResult() == ButtonType.OK) {
            alert.close();
        }
    }
    
    public void EnviarTramaARP(String destino)throws Exception
    {   
        Envio.EnvioARP.arp(InetAddress.getByName(destino));
    }
    
    public void EnviarTramaICMP(String destino, String Origen, int tam, boolean seleccion)throws Exception
    {
        if(Origen == null)
            Envio.EnvioICMP.sendICMP(InetAddress.getByName(destino),null,tam,seleccion);
        else
            Envio.EnvioICMP.sendICMP(InetAddress.getByName(destino),InetAddress.getByName(Origen),tam,seleccion);
    }
    
}
