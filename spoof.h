#pragma once

#include <pcap.h>
#include <cstring>   
#include <unistd.h>  
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h> 
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};


#pragma pack(pop)


class Spoof {
    public:
        void GetAttackerMac(const char* interface);
        void GetAttackerIP(const char* interface);
        void SetSendnTargetIp(char* senderIP, char* targetIP);
        void SetDefaultArpPacket(struct EthArpPacket& packet);
        void SetPacket(struct EthArpPacket &packet, Mac dmac, Mac smac, uint16_t op, Ip sip, Mac tmac, Ip tip);
        void SendArpPacket(pcap_t* pcap,  const EthArpPacket* packet);
        void GetSrcMac(pcap_t* pcap, std::string SendORTarget);
        int RelayPacket(pcap_t* pcap);

        Mac senderMac_;
        Mac targetMac_;
        Mac attackerMac_;

        Ip senderIP_;
        Ip targetIP_;
        Ip attackerIP_;


    private:


};