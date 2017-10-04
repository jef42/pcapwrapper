#include "../../../include/network/packages/ethernetpackage.h"

#include "../../../include/helpers/constants.h"
#include <netinet/in.h>
#include <string.h>

namespace PCAP {

EthernetPackage::EthernetPackage(const uchar *p, uint l,
                                 bool modify)
    : BasePackage{p, l, modify} {
    m_ethernet = (struct sniffethernet *)m_package;
}

MacAddress EthernetPackage::get_src_mac() const {
    return MacAddress(m_ethernet->m_ether_shost);
}

MacAddress EthernetPackage::get_dst_mac() const {
    return MacAddress(m_ethernet->m_ether_dhost);
}

ushort EthernetPackage::get_ether_type() const {
    return ntohs(m_ethernet->m_ether_type);
}

void EthernetPackage::set_src_mac(MacAddress mac) {
    memcpy(m_ethernet->m_ether_shost, mac.data(), ethernet_addr_len);
}

void EthernetPackage::set_dst_mac(MacAddress mac) {
    memcpy(m_ethernet->m_ether_dhost, mac.data(), ethernet_addr_len);
}

void EthernetPackage::set_ether_type(ushort type) {
    m_ethernet->m_ether_type = htons(type);
}

bool operator==(const EthernetPackage &lhs, const EthernetPackage &rhs) {
    return memcmp(lhs.m_ethernet, rhs.m_ethernet, sizeof(sniffethernet)) == 0;
}

bool operator!=(const EthernetPackage &lhs, const EthernetPackage &rhs) {
    return !(lhs == rhs);
}
}
