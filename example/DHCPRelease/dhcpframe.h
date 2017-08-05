#ifndef DHCPFRAME_H
#define DHCPFRAME_H

struct sniffdhcp {
    unsigned char m_op;
    unsigned char m_type;
    unsigned char m_hlen;
    unsigned char m_hops;
    unsigned int m_transaction;
    unsigned short m_secs;
    unsigned short m_flags;
    unsigned char m_ciaddr[4];
    unsigned char m_yiaddr[4];
    unsigned char m_siaddr[4];
    unsigned char m_giaddr[4];
    unsigned char m_chaddr[16];
    unsigned char m_legacy[192];
};

#endif // DHCPFRAME_H
