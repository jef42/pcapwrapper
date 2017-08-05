#ifndef KEYS_H
#define KEYS_H

namespace PCAP {
namespace PCAPBuilder {

enum class Keys {
    Key_Eth_Mac_Dst,
    Key_Eth_Mac_Src,
    Key_Ip_Src,
    Key_Ip_Dst,
    Key_Ip_TTL,
    Key_Ip_Flags,
    Key_Ip_Id,
    Key_Ip_Length,
    Key_Arp_Mac_Src,
    Key_Arp_Mac_Dst,
    Key_Arp_Opcode,
    Key_Udp_Length,
    Key_Src_Port,
    Key_Dst_Port,
    Key_Icmp_Type,
    Key_Icmp_Code,
    Key_Tcp_SeqNr,
    Key_Tcp_AckNr,
    Key_Tcp_Flags,
};

}
}

#endif // KEYS_H
