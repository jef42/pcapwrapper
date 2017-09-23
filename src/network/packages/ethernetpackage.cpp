#include "../../../include/network/packages/ethernetpackage.h"

#include "../../../include/helpers/constants.h"
#include <netinet/in.h>
#include <string.h>

namespace PCAP {

EthernetPackage::EthernetPackage(const unsigned char *p, unsigned int l,
                                 bool modify)
    : BasePackage{p, l, modify} {
    m_ethernet = (struct sniffethernet *)m_package;
}

MacAddress EthernetPackage::getSrcMac() const {
    return MacAddress(m_ethernet->m_ether_shost);
}

MacAddress EthernetPackage::getDstMac() const {
    return MacAddress(m_ethernet->m_ether_dhost);
}

unsigned short EthernetPackage::getEtherType() const {
    return ntohs(m_ethernet->m_ether_type);
}

void EthernetPackage::setSrcMac(MacAddress mac) {
    memcpy(m_ethernet->m_ether_shost, mac.data(), ethernet_addr_len);
}

void EthernetPackage::setDstMac(MacAddress mac) {
    memcpy(m_ethernet->m_ether_dhost, mac.data(), ethernet_addr_len);
}

void EthernetPackage::setEtherType(unsigned short type) {
    m_ethernet->m_ether_type = htons(type);
}

bool operator==(const EthernetPackage &lhs, const EthernetPackage &rhs) {
    return memcmp(lhs.m_ethernet, rhs.m_ethernet, sizeof(sniffethernet)) == 0;
}

bool operator!=(const EthernetPackage &lhs, const EthernetPackage &rhs) {
    return !(lhs == rhs);
}
}
