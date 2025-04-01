#pragma once

#include "ip.h"

#pragma pack(1)
struct IpHdr {
    uint8_t VersionAndIhl;
    uint8_t TOS;
    uint16_t TotalLength;

    uint16_t Identification;
    uint16_t FlagAndFragmentOffset;

    uint8_t TTL;
    uint8_t Protocol;
    uint16_t HeaderChecksum;

    Ip Sip;
    Ip Dip;

};