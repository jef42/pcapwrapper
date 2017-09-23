#ifndef SNIFFETHERNET_H
#define SNIFFETHERNET_H

#include "../../helpers/constants.h"

namespace PCAP {

struct sniffethernet {
    unsigned char
        m_ether_dhost[ethernet_addr_len]; /* destination host address */
    unsigned char m_ether_shost[ethernet_addr_len]; /* source host address */
    unsigned short m_ether_type;                    /* IP? ARP? RARP? etc */
};
}

#endif // ETHERNETPCAP_H
