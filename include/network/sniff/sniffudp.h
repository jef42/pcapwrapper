#ifndef SNIFFUDP_H
#define SNIFFUDP_H

namespace PCAP {

struct sniffudp {
    ushort m_th_sport; /* source port */
    ushort m_th_dport; /* destination port */
    ushort m_length;
    ushort m_checksum;
};

static_assert(sizeof(sniffudp) == 8, "Size of UDP must be 8");

}

#endif // SNIFFUDP_H
