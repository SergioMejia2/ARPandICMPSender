/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils;

import java.net.InetAddress;

/**
 *
 * @author Sergio A. Mejía
 */
public class Utils
{
    public static byte[] shortToByte(short val)
    {
        
        byte[] arr = new byte[]
            {
                (byte) (val >>> 8), (byte) (val & 0xFF)
            };
        return arr;
    }
    
    public static void printBytes(byte[] arr)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb.toString());
    }

    public static String bytesToString(byte[] arr)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : arr)
        {
            sb.append(String.format("%02X:", b));
        }
        return sb.deleteCharAt(sb.length()-1).toString();
    }
}
