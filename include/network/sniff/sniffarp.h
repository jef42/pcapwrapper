#ifndef SNIFFARP_H
#define SNIFFARP_H

#include "../../helpers/common.h"
#include "../../helpers/constants.h"

namespace PCAP {

struct sniffarp {
    ushort m_hardware_type;
    ushort m_protocol;
    uchar m_hardware_address_length;
    uchar m_protocol_address_length;
    ushort m_opcode;
    uchar m_sender_hardware_address[ethernet_addr_len];
    uchar m_sender_ip_address[ip_addr_len];
    uchar m_target_harware_address[ethernet_addr_len];
    uchar m_target_ip_address[ip_addr_len];
};

static_assert(sizeof(sniffarp) == 28, "Size of ARP must be 28");
}

#endif // SNIFFARP_H
