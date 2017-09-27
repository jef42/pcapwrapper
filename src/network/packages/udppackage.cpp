#include "../../../include/network/packages/udppackage.h"

#include <netinet/in.h>
#include <string.h>

#include "../../../include/helpers/helper.h"

namespace PCAP {

UDPPackage::UDPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_udp = (struct sniffudp *)(m_package + size_ethernet + 5 * 4);
    m_data = &m_package[size_ethernet + 5 * 4 + sizeof(*m_udp)];
}

unsigned short UDPPackage::get_src_port() const {
    return ntohs(m_udp->m_th_sport);
}

unsigned short UDPPackage::get_dst_port() const {
    return ntohs(m_udp->m_th_dport);
}

unsigned short UDPPackage::get_udp_length() const {
    return ntohs(m_udp->m_length);
}

void UDPPackage::set_src_port(unsigned short src_port) {
    m_udp->m_th_sport = htons(src_port);
}

void UDPPackage::set_dst_port(unsigned short dst_port) {
    m_udp->m_th_dport = htons(dst_port);
}

void UDPPackage::set_udp_length(unsigned short length) {
    m_udp->m_length = htons(length);
}

void UDPPackage::recalculate_checksums() {
    PCAPHelper::set_ip_checksum(m_ip);
    PCAPHelper::set_udp_checksum(m_ip, m_udp, m_data);
}

const unsigned char *UDPPackage::get_data() const { return m_data; }

unsigned int UDPPackage::get_data_length() const {
    return ntohs(m_udp->m_length) - 8;
}

void UDPPackage::append_data(unsigned char *data, int size) {
    memcpy(&m_package[get_length()], (char *)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
    m_udp->m_length = htons(ntohs(m_udp->m_length) + size);
}

unsigned int UDPPackage::get_length() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

bool operator==(const UDPPackage &lhs, const UDPPackage &rhs) {
    return static_cast<const IPPackage &>(lhs) ==
               static_cast<const IPPackage &>(rhs) &&
           memcmp(lhs.m_udp, rhs.m_udp, sizeof(sniffudp)) == 0;
}

bool operator!=(const UDPPackage &lhs, const UDPPackage &rhs) {
    return !(lhs == rhs);
}
}
