#ifndef SNIFFETHERNET_H
#define SNIFFETHERNET_H

#include "../../helpers/common.h"
#include "../../helpers/constants.h"

namespace PCAP {

struct sniffethernet {
    uchar m_ether_dhost[ethernet_addr_len]; /* destination host address */
    uchar m_ether_shost[ethernet_addr_len]; /* source host address */
    ushort m_ether_type;                    /* IP? ARP? RARP? etc */
};

static_assert(sizeof(sniffethernet) == 14, "Size of Ethernet must be 14");
}

#endif // ETHERNETPCAP_H
