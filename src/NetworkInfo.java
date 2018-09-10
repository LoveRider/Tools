import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

import static java.lang.System.out;

public class NetworkInfo {

    private ArrayList<NetworkInterface> activeInt = new ArrayList<>();
    private InetAddress address;
    private byte[] mac;
    NetworkInfo(){
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)) {
                if (netint.isUp() && !netint.isLoopback()) {
                    activeInt.add(netint);
                }
            }
        }catch (SocketException ex){
            ex.printStackTrace();
        }
    }

    public void getNetworkInterfaces(){
        try{
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)){
                if(netint.isUp() && !netint.isLoopback()) {
                    out.printf("Display name: %s\n", netint.getDisplayName());
                    out.printf("Name: %s\n", netint.getName());
                    Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
                    for (InetAddress inetAddress : Collections.list(inetAddresses)) {
                        out.printf("InetAddress: %s\n", inetAddress);
                    }
                    out.printf("\n");
                }
            }
            System.out.println(activeInt.size());
        }catch (SocketException ex){
            ex.printStackTrace();
        }
    }

    public byte[] getMac(){
        NetworkInterface network;
        StringBuilder sb = new StringBuilder();
        try{
            if(activeInt.size() == 1){
                network = activeInt.get(0);
                mac = network.getHardwareAddress();
                System.out.print("Current MAC address : ");

                for (int i = 0; i < mac.length; i++) {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                System.out.println(sb.toString());
            }
            else{
                //Выбор интерфейса. Доделать позже, когда будет GUI.
                network = NetworkInterface.getByName("wlan2");
                mac = network.getHardwareAddress();
                System.out.print("Current MAC address : ");

                for (int i = 0; i < mac.length; i++) {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                System.out.println(sb.toString());
            }

        }catch (SocketException ex) {
            ex.printStackTrace();
        }
        return mac;
    }

    public  byte[] getIP(){
        byte[] ip = null;
        NetworkInterface network;
        try{
            if(activeInt.size() == 1){
                address = InetAddress.getLocalHost();
                ip = address.getAddress();
                System.out.println("Current IP Address: " +
                        (0xff & (int) ip[0]) + "." +
                        (0xff & (int) ip[1]) + "." +
                        (0xff & (int) ip[2]) + "." +
                        (0xff & (int) ip[3]));
            }
            else {
                network = NetworkInterface.getByName("wlan2");
                Enumeration<InetAddress> addressList = network.getInetAddresses();

                while (addressList.hasMoreElements()) {
                    InetAddress inetAddress = addressList.nextElement();
                    if (inetAddress.isSiteLocalAddress()) {
                        ip = inetAddress.getAddress();
                        System.out.println("Current IP Address: " +
                                (0xff & (int) ip[0]) + "." +
                                (0xff & (int) ip[1]) + "." +
                                (0xff & (int) ip[2]) + "." +
                                (0xff & (int) ip[3]));
                    }
                }
            }
        }catch (SocketException ex) {
            ex.printStackTrace();
        }catch (UnknownHostException ex){
            ex.printStackTrace();
        }
        return ip;
    }

    public int hostsNumber(){
        int hosts = 0;
        NetworkInterface network;
        try{
            if(activeInt.size() == 1){
                address = InetAddress.getLocalHost();
                network = NetworkInterface.getByInetAddress(address);
                int subMask = 32 - network.getInterfaceAddresses().get(0).getNetworkPrefixLength();
                hosts = (int) Math.pow(2, subMask) - 2;
            }
        }catch (SocketException ex) {
            ex.printStackTrace();
        }catch (UnknownHostException ex){
            ex.printStackTrace();
        }
        return hosts;
    }
}
