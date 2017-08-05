#include "arppackage.h"

#include <netinet/in.h>
#include <cstring>

#include "../../helpers/constants.h"

namespace PCAP {

ARPPackage::ARPPackage(const unsigned char *p, unsigned int l)
    : EthernetPackage{p, l} {
    m_arp = (struct sniffarp*)(m_package + SIZE_ETHERNET);
}

IpAddress ARPPackage::getSrcIp() const {
    return IpAddress(m_arp->m_sender_ip_address);
}

MacAddress ARPPackage::getSrcArpMac() const {
    return MacAddress(m_arp->m_sender_hardware_address);
}

IpAddress ARPPackage::getDstIp() const {
    return IpAddress(m_arp->m_target_ip_address);
}

MacAddress ARPPackage::getDstArpMac() const {
    return MacAddress(m_arp->m_target_harware_address);
}

void ARPPackage::setSrcIp(IpAddress ip) {
    memcpy(m_arp->m_sender_ip_address, ip.data(), IP_ADDR_LEN);
}

void ARPPackage::setDstIp(IpAddress ip) {
    memcpy(m_arp->m_target_ip_address, ip.data(), IP_ADDR_LEN);
}

void ARPPackage::setSrcArpMac(MacAddress mac) {
    memcpy(m_arp->m_sender_hardware_address, mac.data(), ETHER_ADDR_LEN);
}

void ARPPackage::setDstArpMac(MacAddress mac) {
    memcpy(m_arp->m_target_harware_address, mac.data(), ETHER_ADDR_LEN);
}

void ARPPackage::setHardwareType(unsigned short type) {
    m_arp->m_hardware_type = htons(type);
}

unsigned short ARPPackage::getHardwareType() const {
    return ntohs(m_arp->m_hardware_type);
}

void ARPPackage::setProtocol(unsigned short proto) {
    m_arp->m_protocol = htons(proto);
}

unsigned short ARPPackage::getProtocol() const {
    return ntohs(m_arp->m_protocol);
}

void ARPPackage::setHardwareLength(unsigned char l) {
    m_arp->m_hardware_address_length = l;
}

unsigned char ARPPackage::getHardwareLength() const {
    return m_arp->m_hardware_address_length;
}

void ARPPackage::setProtocolLength(unsigned char l) {
    m_arp->m_protocol_address_length = l;
}

unsigned char ARPPackage::getProtocolLength() const {
    return m_arp->m_protocol_address_length;
}

void ARPPackage::setOpcode(unsigned short code) {
    m_arp->m_opcode = htons(code);
}

unsigned short ARPPackage::getOpcode() const {
    return ntohs(m_arp->m_opcode);
}

unsigned int ARPPackage::getLength() const {
    return sizeof(*m_ethernet) + sizeof(*m_arp);
}

}
