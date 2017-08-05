#ifndef SNIFFUDP_H
#define SNIFFUDP_H

namespace PCAP {

struct sniffudp {
    unsigned short m_th_sport;               /* source port */
    unsigned short m_th_dport;               /* destination port */
    unsigned short m_length;
    unsigned short m_checksum;
};

}

#endif // SNIFFUDP_H
