#include "ethernetpackage.h"

#include "../../helpers/constants.h"
#include <netinet/in.h>
#include <string.h>

namespace PCAP {

EthernetPackage::EthernetPackage(const unsigned char* p,unsigned int l)
    : BasePackage{p, l}
{
    m_ethernet = (struct sniffethernet*)m_package;
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
    memcpy(m_ethernet->m_ether_shost, mac.data(), ETHER_ADDR_LEN);
}

void EthernetPackage::setDstMac(MacAddress mac) {
    memcpy(m_ethernet->m_ether_dhost, mac.data(), ETHER_ADDR_LEN);
}

void EthernetPackage::setEtherType(unsigned short type) {
    m_ethernet->m_ether_type = htons(type);
}

}
