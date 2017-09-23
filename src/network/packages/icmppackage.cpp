#include "../../../include/network/packages/icmppackage.h"

#include <netinet/in.h>
#include <cstring>

#include "../../../include/helpers/helper.h"

namespace PCAP {

ICMPPackage::ICMPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_icmp = (struct snifficmp*)(m_package + sizeof(sniffethernet) + sizeof(sniffip));
    m_data = (unsigned char*)(m_package + sizeof(sniffethernet) + sizeof(sniffip) + sizeof(snifficmp));
}

unsigned char ICMPPackage::getType() const {
    return m_icmp->m_type;
}

void ICMPPackage::setType(unsigned char type) {
    m_icmp->m_type = type;
}

unsigned char ICMPPackage::getCode() const {
    return m_icmp->m_code;
}

void ICMPPackage::setCode(unsigned char code) {
    m_icmp->m_code = code;
}

void ICMPPackage::recalculateChecksums() {
    PCAPHelper::setIPChecksum(m_ip);
    PCAPHelper::setICMPChecksum(m_ip, m_icmp);
}

const unsigned char* ICMPPackage::getData() const {
    return m_data;
}

unsigned int ICMPPackage::getDataLength() const {
    return ntohs(m_ip->m_ip_len) - sizeof(*m_icmp) - sizeof(*m_ip);
}

void ICMPPackage::appendData(unsigned char* data, int size) {
    memcpy(&m_package[getLength()], (char*)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
}

unsigned int ICMPPackage::getLength() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

bool operator==(const ICMPPackage &lhs, const ICMPPackage &rhs) {
    return static_cast<const IPPackage&>(lhs) == static_cast<const IPPackage&>(rhs) &&
           memcmp(lhs.m_icmp, rhs.m_icmp, sizeof(snifficmp)) == 0;
}

bool operator!=(const ICMPPackage &lhs, const ICMPPackage &rhs) {
    return !(lhs == rhs);
}

}
