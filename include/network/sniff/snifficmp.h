#ifndef SNIFFICMP_H
#define SNIFFICMP_H

namespace PCAP {

struct snifficmp {
    unsigned char m_type;
    unsigned char m_code;
    unsigned short m_checksum;
    unsigned int m_rest_header;
};

static_assert(sizeof(snifficmp) == 8, "Size of ICMP must be 8");
}

#endif // SNIFFICMP_H
