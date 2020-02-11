package Envio;


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;
import org.pcap4j.packet.Packet;


/**
 * This class represents ARP/RARP packet.
 */
public class ARPPacket
{
    public static short HARDTYPE_ETHER = 1;
    /**
     * Hardware type: Token ring
     */
    public static final short HARDTYPE_IEEE802 = 6;
    /**
     * Hardware type: Frame relay
     */
    public static final short HARDTYPE_FRAMERELAY = 15;
    /**
     * Protocol type: IP
     */
    public static final short PROTOTYPE_IP = 2048;
    /**
     * ARP request
     */
    public static final short ARP_REQUEST = 1;
    /**
     * ARP reply
     */
    public static final short ARP_REPLY = 2;
    /**
     * Reverse ARP request
     */
    public static final short RARP_REQUEST = 3;
    /**
     * Reverse ARP reply
     */
    public static final short RARP_REPLY = 4;
    /**
     * Identify peer request
     */
    public static final short INV_REQUEST = 8;
    /**
     * Identify peer response
     */
    public static final short INV_REPLY = 9;

    private byte[] frame;
    
    ARPPacket()
    {
        frame = new byte[60];
        setVals();
    }

    void setVals()
    {
        for(int i = 0; i < 6; i++)
        {
            this.frame[i] = (byte)0xff;
        }
        for(int i = 32; i < 38; i++)
        {
            this.frame[i] = (byte)0x0;
        }
        frame[18] = (byte)6;
        frame[19] = (byte)4;
        byte[] opCode = Utils.Utils.shortToByte((short)1);
        frame[20] = opCode[0];
        frame[21] = opCode[1];
        byte[] type = Utils.Utils.shortToByte((short)0x806);
        frame[12] = type[0];
        frame[13] = type[1];
        byte[] hwaddspace = Utils.Utils.shortToByte((short)1);
        frame[14] = hwaddspace[0];
        frame[15] = hwaddspace[1];
        byte[] protoaddspace = Utils.Utils.shortToByte((short)0x0800);
        frame[16] = protoaddspace[0];
        frame[17] = protoaddspace[1];
        for(int i = 42; i < frame.length; i++) //PADDING
        {
            frame[i] = (byte)0;
        }
    }
    
    public byte[] getBytes()
    {
        return this.frame;
    }

    void addHardwareAddressSpace(short hardtype_e)
    {
        byte[] hardtype = Utils.Utils.shortToByte(hardtype_e);
        
    }

    void setDestinationIP(byte[] address)
    {
        for(int i = 0; i < address.length; i++)
        {
            frame[i+38] = address[i];
        }
    }

    void setOriginIP(byte[] address)
    {
        for(int i = 0; i < address.length; i++)
        {
            frame[i+28] = address[i];
        }
    }

    void setOriginMAC(byte[] address)
    {
        for(int i = 0; i < address.length; i++)
        {
            frame[i+6] = address[i];
        }
        for(int i = 0; i < address.length; i++)
        {
            frame[i+22] = address[i];
        }
    }
}