#ifndef SNIFFTCP_H
#define SNIFFTCP_H

namespace PCAP {

struct snifftcp {
    ushort m_th_sport; /* source port */
    ushort m_th_dport; /* destination port */
    uint m_th_seq;     /* sequence number */
    uint m_th_ack;     /* acknowledgement number */
    uchar m_th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->m_th_offx2 & 0xf0) >> 4)
    uchar m_th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    ushort m_th_win; /* window */
    ushort m_th_sum; /* checksum */
    ushort m_th_urp; /* urgent pointer */
};

struct snifftcpopt {
    uchar opt[40];
};

static_assert(sizeof(snifftcp) == 20, "Size of TCP must be 20");

}

#endif // SNIFFTCP_H
