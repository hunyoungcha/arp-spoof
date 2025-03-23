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

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


class Spoof {
    public:
        Mac GetAttackerMac(const char* interface);
        Ip GetAttackerIP(const char* interface);
        void SetSendnTargetIp(char* senderIP, char* targetIP);
        void SetArpPacketDefault(struct EthArpPacket& packet);
        void SetPacket(struct EthArpPacket &packet, Mac dmac, Mac smac, uint16_t op, Ip sip, Mac tmac, Ip tip);
        void SendPacket(pcap_t* pcap, struct EthArpPacket& packet);
        void GetSenderMac(pcap_t* pcap);

        Mac senderMac_;
        Mac targetMac_;

        Ip senderIP_;
        Ip targetIP_;

    private:


};