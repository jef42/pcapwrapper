#ifndef SNIFFIP_H
#define SNIFFIP_H

namespace PCAP {

struct sniffip {
    unsigned char m_ip_vhl;  /* version << 4 | header length >> 2 */
    unsigned char m_ip_tos;  /* type of service */
    unsigned short m_ip_len; /* total length */
    unsigned short m_ip_id;  /* identification */
    unsigned short m_ip_off; /* fragment offset field */
#define IP_RF 0x8000         /* reserved fragment flag */
#define IP_DF 0x4000         /* dont fragment flag */
#define IP_MF 0x2000         /* more fragments flag */
#define IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
    unsigned char m_ip_ttl;  /* time to live */
    unsigned char m_ip_p;    /* protocol */
    unsigned short m_ip_sum; /* checksum */
    unsigned char m_ip_src[4];
    unsigned char m_ip_dst[4];
};

static_assert(sizeof(sniffip) == 20, "Size of IP must be 20");
}

#endif // IPPCAP_H
