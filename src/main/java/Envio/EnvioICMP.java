/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Envio;

import java.io.IOException;
import java.net.InetAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javafx.concurrent.Task;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

/**
 *
 * @author julia
 */
public class EnvioICMP
{

    private static final String COUNT_KEY = EnvioICMP.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

    private static final String READ_TIMEOUT_KEY = EnvioICMP.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = EnvioICMP.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final String MTU_KEY = EnvioICMP.class.getName() + ".mtu";
    private static final int MTU = Integer.getInteger(MTU_KEY, 1403); // [bytes]

    static void sendICMP(InetAddress destino, InetAddress origen, int tam, boolean seleccion) throws Exception
    {
        //String strSrcIpAddress = args[0]; // for InetAddress.getByName()
        String strSrcMacAddress = "";//args[1]; // e.g. 12:34:56:ab:cd:ef
        //String strDstIpAddress = args[2]; // for InetAddress.getByName()
        String strDstMacAddress = ""; // e.g. 12:34:56:ab:cd:ef

        if (tam >= 65536)
        {
            throw new IllegalArgumentException("Ha excedido el tamaño maximo de los datos.");
        }

        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        nif = Facade.nif;

        if (nif == null)
        {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle sendHandle
                = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        //System.out.println("ME LLEGO"+seleccion+" CON TAMAÑO "+tam);
        List<PcapAddress> lista = nif.getAddresses();
            
        if(!seleccion)
        {
            if(origen.getHostAddress().equals(lista.get(1).getAddress().getHostAddress()))
            {
                seleccion = true;
            }
            else
                strSrcMacAddress = Utils.Utils.bytesToString(EnvioARP.arp(origen).getAddress());
            
        }
        if (seleccion)
         {
            origen = lista.get(1).getAddress();
            
            List<LinkLayerAddress> lista2 = nif.getLinkLayerAddresses();
            strSrcMacAddress = Utils.Utils.bytesToString(lista2.get(0).getAddress());
        }
        strDstMacAddress = Utils.Utils.bytesToString(EnvioARP.arp(destino).getAddress());
        System.out.println("WHAT");
        MacAddress srcMacAddr = MacAddress.getByName(strSrcMacAddress, ":");
        try
        {

            byte[] echoData = new byte[tam - 28];
            for (int i = 0;
                    i < echoData.length;
                    i++)
            {
                echoData[i] = (byte) i;
            }

            IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();

            echoBuilder.identifier(
                    (short) 1)
                    .payloadBuilder(
                            new UnknownPacket.Builder().rawData(echoData));

            IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();

            icmpV4CommonBuilder.type(IcmpV4Type.ECHO)
                    .code(IcmpV4Code.NO_CODE)
                    .payloadBuilder(echoBuilder)
                    .correctChecksumAtBuild(true);

            IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();

            ipV4Builder.version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl(
                            (byte) 100)
                    .protocol(IpNumber.ICMPV4)
                    .srcAddr((Inet4Address) origen)
                    .dstAddr((Inet4Address) destino)
                    .payloadBuilder(icmpV4CommonBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();

            etherBuilder.dstAddr(MacAddress.getByName(strDstMacAddress, ":"))
                    .srcAddr(srcMacAddr)
                    .type(EtherType.IPV4)
                    .paddingAtBuild(true);

            for (int i = 0;
                    i < 1;
                    i++)
            {
                echoBuilder.sequenceNumber((short) i);
                ipV4Builder.identification((short) i);

                for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4Builder.build(), MTU))
                {
                    etherBuilder.payloadBuilder(
                            new AbstractBuilder()
                    {
                        @Override
                        public Packet build()
                        {
                            return ipV4Packet;
                        }
                    }
                    );
                    Packet p = etherBuilder.build();
                    System.out.println("AMMMMMMM");

                    sendHandle.sendPacket(p);

                    try
                    {
                        Thread.sleep(100);
                    } catch (InterruptedException e)
                    {
                        break;
                    }
                }

                try
                {
                    Thread.sleep(1000);
                } catch (InterruptedException e)
                {
                    break;
                }
            }
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            if (sendHandle != null && sendHandle.isOpen())
            {
                System.out.println("Closing");
                sendHandle.close();
            }
            if (pool != null && !pool.isShutdown())
            {
                pool.shutdown();
            }
        }
    }
}
