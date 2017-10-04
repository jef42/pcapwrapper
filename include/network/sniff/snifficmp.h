#ifndef SNIFFICMP_H
#define SNIFFICMP_H

namespace PCAP {

struct snifficmp {
    uchar m_type;
    uchar m_code;
    ushort m_checksum;
    uint m_rest_header;
};

static_assert(sizeof(snifficmp) == 8, "Size of ICMP must be 8");
}

#endif // SNIFFICMP_H
