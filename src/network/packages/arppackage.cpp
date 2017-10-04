#include "../../../include/network/packages/arppackage.h"

#include <cstring>
#include <netinet/in.h>

#include "../../../include/helpers/constants.h"

namespace PCAP {

ARPPackage::ARPPackage(const uchar *p, uint l, bool modify)
    : EthernetPackage{p, l, modify} {
    m_arp = (struct sniffarp *)(m_package + size_ethernet);
}

IpAddress ARPPackage::get_src_ip() const {
    return IpAddress(m_arp->m_sender_ip_address);
}

MacAddress ARPPackage::get_src_arp_mac() const {
    return MacAddress(m_arp->m_sender_hardware_address);
}

IpAddress ARPPackage::get_dst_ip() const {
    return IpAddress(m_arp->m_target_ip_address);
}

MacAddress ARPPackage::get_dst_arp_mac() const {
    return MacAddress(m_arp->m_target_harware_address);
}

void ARPPackage::set_src_ip(IpAddress ip) {
    memcpy(m_arp->m_sender_ip_address, ip.data(), ip_addr_len);
}

void ARPPackage::set_dst_ip(IpAddress ip) {
    memcpy(m_arp->m_target_ip_address, ip.data(), ip_addr_len);
}

void ARPPackage::set_src_arp_mac(MacAddress mac) {
    memcpy(m_arp->m_sender_hardware_address, mac.data(), ethernet_addr_len);
}

void ARPPackage::set_dst_arp_mac(MacAddress mac) {
    memcpy(m_arp->m_target_harware_address, mac.data(), ethernet_addr_len);
}

void ARPPackage::set_hardware_type(ushort type) {
    m_arp->m_hardware_type = htons(type);
}

ushort ARPPackage::get_hardware_type() const {
    return ntohs(m_arp->m_hardware_type);
}

void ARPPackage::set_protocol(ushort proto) {
    m_arp->m_protocol = htons(proto);
}

ushort ARPPackage::get_protocol() const {
    return ntohs(m_arp->m_protocol);
}

void ARPPackage::set_hardware_length(uchar l) {
    m_arp->m_hardware_address_length = l;
}

uchar ARPPackage::get_hardware_length() const {
    return m_arp->m_hardware_address_length;
}

void ARPPackage::set_protocol_length(uchar l) {
    m_arp->m_protocol_address_length = l;
}

uchar ARPPackage::get_protocol_length() const {
    return m_arp->m_protocol_address_length;
}

void ARPPackage::set_opcode(ushort code) {
    m_arp->m_opcode = htons(code);
}

ushort ARPPackage::get_opcode() const { return ntohs(m_arp->m_opcode); }

uint ARPPackage::get_length() const {
    return sizeof(*m_ethernet) + sizeof(*m_arp);
}

bool operator==(const ARPPackage &lhs, const ARPPackage &rhs) {
    return static_cast<const EthernetPackage &>(lhs) ==
               static_cast<const EthernetPackage &>(rhs) &&
           memcmp(lhs.m_arp, rhs.m_arp, sizeof(sniffarp)) == 0;
}

bool operator!=(const ARPPackage &lhs, const ARPPackage &rhs) {
    return !(lhs == rhs);
}
}
