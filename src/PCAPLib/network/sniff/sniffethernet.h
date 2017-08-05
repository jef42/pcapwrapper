#ifndef SNIFFETHERNET_H
#define SNIFFETHERNET_H

#include "../../helpers/constants.h"

namespace PCAP {

struct sniffethernet {
    unsigned char  m_ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    unsigned char  m_ether_shost[ETHER_ADDR_LEN];    /* source host address */
    unsigned short m_ether_type;                     /* IP? ARP? RARP? etc */
};

}

#endif // ETHERNETPCAP_H
