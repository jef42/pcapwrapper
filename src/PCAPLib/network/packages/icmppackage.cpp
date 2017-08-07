#include "icmppackage.h"

#include <netinet/in.h>
#include <cstring>

#include "../../helpers/helper.h"

namespace PCAP {

ICMPPackage::ICMPPackage(const unsigned char *p, unsigned int l)
    : IPPackage{p, l} {
    m_icmp = (struct snifficmp*)(m_package + size_ethernet + 5*4);
    m_data = (unsigned char*)(m_package + size_ethernet + 5*4 + sizeof(snifficmp));
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
    PCAPHelper::setICMPChecksum(m_icmp);
}

const unsigned char* ICMPPackage::getData() const {
    return m_data;
}

unsigned int ICMPPackage::getDataLength() const {
    return ntohs(m_ip->m_ip_len) - sizeof(m_icmp) - sizeof(m_ip);
}

void ICMPPackage::appendData(unsigned char* data, int size) {
    memcpy(&m_package[getDataLength()], (char*)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
}

unsigned int ICMPPackage::getLength() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

}
