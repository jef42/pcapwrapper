#ifndef PCAPCONSTANTS_H
#define PCAPCONSTANTS_H

/* default snap length (maximum bytes per package to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define IP_ADDR_LEN 4

#define IP_HL(ip)               (((ip)->m_ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->m_ip_vhl) >> 4)

#endif // PCAPCONSTANTS_H
