#ifndef DHCPFRAME_H
#define DHCPFRAME_H

#include <pcapwrapper/helpers/common.h>

struct sniffdhcp {
    PCAP::uchar m_op;
    PCAP::uchar m_type;
    PCAP::uchar m_hlen;
    PCAP::uchar m_hops;
    uint m_transaction;
    ushort m_secs;
    ushort m_flags;
    PCAP::uchar m_ciaddr[4];
    PCAP::uchar m_yiaddr[4];
    PCAP::uchar m_siaddr[4];
    PCAP::uchar m_giaddr[4];
    PCAP::uchar m_chaddr[16];
    PCAP::uchar m_legacy[192];
};

#endif // DHCPFRAME_H
