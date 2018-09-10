public class Main {

    public static void main(String[] args) {
        ARP arp = new ARP();
        arp.sendPackets(35);
        arp.capture(50);
        arp.networkDevices();

    }
}
