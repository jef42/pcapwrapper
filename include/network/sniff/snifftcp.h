#ifndef SNIFFTCP_H
#define SNIFFTCP_H

namespace PCAP {

struct snifftcp {
    unsigned short m_th_sport; /* source port */
    unsigned short m_th_dport; /* destination port */
    unsigned int m_th_seq;     /* sequence number */
    unsigned int m_th_ack;     /* acknowledgement number */
    unsigned char m_th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->m_th_offx2 & 0xf0) >> 4)
    unsigned char m_th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    unsigned short m_th_win; /* window */
    unsigned short m_th_sum; /* checksum */
    unsigned short m_th_urp; /* urgent pointer */
};

struct snifftcpopt {
    unsigned char opt[40];
};

static_assert(sizeof(snifftcp) == 20, "Size of TCP must be 20");

}

#endif // SNIFFTCP_H
