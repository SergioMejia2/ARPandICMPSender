package Envio;

import java.io.IOException;
import static java.lang.Thread.sleep;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.LinkLayerAddress;

/**
 *
 * @author pablo
 */
public class EnvioARP
{

    private static final String COUNT_KEY = EnvioARP.class.getName() + ".count";
    private static final int COUNT = 1;//Integer.getInteger(COUNT_KEY, 5);

    private static final String READ_TIMEOUT_KEY
            = EnvioARP.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT
            = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY
            = EnvioARP.class.getName() + ".snaplen";
    private static final int SNAPLEN
            = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    public static MacAddress resolvedAddr = null;
    private static boolean encontro;

    /* 
 * @param ip address containing an IP
 * @return MAC-Address as formatted String
 * @throws IOException
 * @throws IllegalArgumentException
     */
    public static MacAddress arp(InetAddress ip) throws Exception
    {
        resolvedAddr = null;
        MacAddress retorno = null;
        PcapNetworkInterface nif = Facade.nif;
        //open pcap4j
        PcapHandle handle;
        handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        //find network interface
        try
        {
            System.out.println("Nif: " + nif.getDescription());
            handle.setFilter(
                    "arp and src host " + ip.getHostAddress(), BpfCompileMode.OPTIMIZE);

            PacketListener listener;
            listener = new PacketListener()
            {
                @Override
                public void gotPacket(Packet packet)
                {
                    if (packet.contains(ArpPacket.class))
                    {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        if (arp.getHeader().getOperation().equals(ArpOperation.REPLY))
                        {
                            EnvioARP.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
                            EnvioARP.encontro = true;

                        }
                    }
                    System.out.println(packet);
                }
            };

            Task t = new Task(handle, listener);
            pool.execute(t);

            ARPPacket packet = new ARPPacket();

            packet.addHardwareAddressSpace(ARPPacket.HARDTYPE_ETHER);
            packet.setDestinationIP(ip.getAddress());
            List<PcapAddress> lista = nif.getAddresses();
            packet.setOriginIP(lista.get(1).getAddress().getAddress());

            List<LinkLayerAddress> lista2 = nif.getLinkLayerAddresses();
            packet.setOriginMAC(lista2.get(0).getAddress());

            //TODO
            sendHandle.sendPacket(packet.getBytes());

        } finally
        {
            if (sendHandle != null && sendHandle.isOpen())
            {
                System.out.println("Cerré ARP");
                sendHandle.close();
            }
            if (pool != null && !pool.isShutdown())
            {
                pool.shutdown();
            }
            if (handle != null && handle.isOpen())
            {
                handle.close();
            }
            if (encontro)
            {
                retorno = resolvedAddr;
            }

            //System.out.println(resolvedAddr+"!!!!");
            return retorno;
        }

        /* byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
        ARPPacket arp=new ARPPacket();
        arp.hardtype=ARPPacket.HARDTYPE_ETHER;
        arp.prototype=ARPPacket.PROTOTYPE_IP;
        arp.operation=ARPPacket.ARP_REQUEST;
        arp.hlen=6;
        arp.plen=4;
        arp.sender_hardaddr=device.mac_address;
        arp.sender_protoaddr=srcip.getAddress();
        arp.target_hardaddr=broadcast;
        arp.target_protoaddr=ip.getAddress();
      
        EthernetPacket ether=new EthernetPacket();
        ether.frametype=EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac=device.mac_address;
        ether.dst_mac=broadcast;
        arp.datalink=ether;
        
        sender.sendPacket(arp);
        while(true){
            ARPPacket p=(ARPPacket)captor.getPacket();
            if(p==null){
                throw new IllegalArgumentException(ip+" is not a local address");
            }
            if(Arrays.equals(p.target_protoaddr,srcip.getAddress())){
                return p.sender_hardaddr;
            }
        }
    }*/
    }

    private static class Task implements Runnable
    {

        private PcapHandle handle;
        private PacketListener listener;

        public Task(PcapHandle handle, PacketListener listener)
        {
            this.handle = handle;
            this.listener = listener;
        }

        @Override
        public void run()
        {
            try
            {
                handle.loop(COUNT, listener);
            } catch (InterruptedException | NotOpenException | PcapNativeException e)
            {
                e.printStackTrace();
                //run();

            }
        }
    }
}
