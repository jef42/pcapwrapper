#include "../../../include/network/packages/icmppackage.h"

#include <cstring>
#include <netinet/in.h>

#include "../../../include/helpers/helper.h"

namespace PCAP {

ICMPPackage::ICMPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_icmp = (struct snifficmp *)(m_package + sizeof(sniffethernet) +
                                  sizeof(sniffip));
    m_data = (unsigned char *)(m_package + sizeof(sniffethernet) +
                               sizeof(sniffip) + sizeof(snifficmp));
}

unsigned char ICMPPackage::get_type() const { return m_icmp->m_type; }

void ICMPPackage::set_type(unsigned char type) { m_icmp->m_type = type; }

unsigned char ICMPPackage::get_code() const { return m_icmp->m_code; }

void ICMPPackage::set_code(unsigned char code) { m_icmp->m_code = code; }

void ICMPPackage::recalculate_checksums() {
    PCAPHelper::set_ip_checksum(m_ip);
    PCAPHelper::set_icmp_checksum(m_ip, m_icmp);
}

const unsigned char *ICMPPackage::get_data() const { return m_data; }

unsigned int ICMPPackage::get_data_length() const {
    return ntohs(m_ip->m_ip_len) - sizeof(*m_icmp) - sizeof(*m_ip);
}

void ICMPPackage::append_data(unsigned char *data, int size) {
    memcpy(&m_package[get_length()], (char *)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
}

unsigned int ICMPPackage::get_length() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

bool operator==(const ICMPPackage &lhs, const ICMPPackage &rhs) {
    return static_cast<const IPPackage &>(lhs) ==
               static_cast<const IPPackage &>(rhs) &&
           memcmp(lhs.m_icmp, rhs.m_icmp, sizeof(snifficmp)) == 0;
}

bool operator!=(const ICMPPackage &lhs, const ICMPPackage &rhs) {
    return !(lhs == rhs);
}
}
