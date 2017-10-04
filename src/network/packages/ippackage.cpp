#include "../../../include/network/packages/ippackage.h"

#include <cstring>
#include <netinet/in.h>

namespace PCAP {

IPPackage::IPPackage(const uchar *p, uint l, bool modify)
    : EthernetPackage{p, l, modify} {
    m_ip = (sniffip *)(m_package + size_ethernet);
}

IpAddress IPPackage::get_src_ip() const { return IpAddress(m_ip->m_ip_src); }

IpAddress IPPackage::get_dst_ip() const { return IpAddress(m_ip->m_ip_dst); }

uchar IPPackage::get_vhl() const { return m_ip->m_ip_vhl; }

uchar IPPackage::get_tos() const { return m_ip->m_ip_tos; }

ushort IPPackage::get_total_length() const {
    return ntohs(m_ip->m_ip_len);
}

ushort IPPackage::get_id() const { return ntohs(m_ip->m_ip_id); }

uchar IPPackage::get_ip_flags() const {
    return ntohs(m_ip->m_ip_off) >> 13;
}

ushort IPPackage::get_fragment_offset() const {
    return ntohs(m_ip->m_ip_off) & IP_OFFMASK;
}

uchar IPPackage::get_ttl() const { return m_ip->m_ip_ttl; }

uchar IPPackage::get_protocol() const { return m_ip->m_ip_p; }

void IPPackage::set_dst_ip(IpAddress ip) {
    memcpy(m_ip->m_ip_dst, ip.data(), ip_addr_len);
}

void IPPackage::set_src_ip(IpAddress ip) {
    memcpy(m_ip->m_ip_src, ip.data(), ip_addr_len);
}

void IPPackage::set_vhl(uchar value) { m_ip->m_ip_vhl = value; }

void IPPackage::set_tos(uchar value) { m_ip->m_ip_tos = value; }

void IPPackage::set_total_length(ushort length) {
    m_ip->m_ip_len = htons(length);
}

void IPPackage::set_id(ushort id) { m_ip->m_ip_id = htons(id); }

void IPPackage::set_ip_flags(uchar flags) {
    m_ip->m_ip_off |= (htons(flags) << 13);
}

void IPPackage::set_fragment_offset(ushort fragment) {
    m_ip->m_ip_off |= (htons(fragment) & IP_OFFMASK);
}

void IPPackage::set_ttl(uchar ttl) { m_ip->m_ip_ttl = ttl; }

void IPPackage::set_protocol(uchar protocol) {
    m_ip->m_ip_p = protocol;
}

bool operator==(const IPPackage &lhs, const IPPackage &rhs) {
    return static_cast<const EthernetPackage &>(lhs) ==
               static_cast<const EthernetPackage &>(rhs) &&
           memcmp(lhs.m_ip, rhs.m_ip, sizeof(sniffip)) == 0;
}

bool operator!=(const IPPackage &lhs, const IPPackage &rhs) {
    return !(lhs == rhs);
}
}
