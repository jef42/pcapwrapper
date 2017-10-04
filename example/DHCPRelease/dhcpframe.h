#ifndef DHCPFRAME_H
#define DHCPFRAME_H

struct sniffdhcp {
    uchar m_op;
    uchar m_type;
    uchar m_hlen;
    uchar m_hops;
    uint m_transaction;
    ushort m_secs;
    ushort m_flags;
    uchar m_ciaddr[4];
    uchar m_yiaddr[4];
    uchar m_siaddr[4];
    uchar m_giaddr[4];
    uchar m_chaddr[16];
    uchar m_legacy[192];
};

#endif // DHCPFRAME_H
