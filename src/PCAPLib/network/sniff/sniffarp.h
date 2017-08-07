#ifndef SNIFFARP_H
#define SNIFFARP_H

#include "../../helpers/constants.h"

namespace PCAP {

struct sniffarp {
    unsigned short m_hardware_type;
    unsigned short m_protocol;
    unsigned char m_hardware_address_length;
    unsigned char m_protocol_address_length;
    unsigned short m_opcode;
    unsigned char m_sender_hardware_address[ethernet_addr_len];
    unsigned char m_sender_ip_address[ip_addr_len];
    unsigned char m_target_harware_address[ethernet_addr_len];
    unsigned char m_target_ip_address[ip_addr_len];
};

}

#endif // SNIFFARP_H
