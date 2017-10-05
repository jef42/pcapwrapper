#ifndef SNIFFIP_H
#define SNIFFIP_H

#include "../../helpers/common.h"

namespace PCAP {

struct sniffip {
    uchar m_ip_vhl;       /* version << 4 | header length >> 2 */
    uchar m_ip_tos;       /* type of service */
    ushort m_ip_len;      /* total length */
    ushort m_ip_id;       /* identification */
    ushort m_ip_off;      /* fragment offset field */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    uchar m_ip_ttl;       /* time to live */
    uchar m_ip_p;         /* protocol */
    ushort m_ip_sum;      /* checksum */
    uchar m_ip_src[4];
    uchar m_ip_dst[4];
};

static_assert(sizeof(sniffip) == 20, "Size of IP must be 20");
}

#endif // IPPCAP_H
