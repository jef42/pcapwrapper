#include "../../../include/network/packages/udppackage.h"

#include <netinet/in.h>
#include <string.h>

#include "../../../include/helpers/helper.h"

namespace PCAP {

UDPPackage::UDPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_udp = (struct sniffudp*)(m_package + size_ethernet + 5*4);
    m_data = &m_package[size_ethernet + 5 * 4 + sizeof(*m_udp)];
}

unsigned short UDPPackage::getSrcPort() const {
    return ntohs(m_udp->m_th_sport);
}

unsigned short UDPPackage::getDstPort() const {
    return ntohs(m_udp->m_th_dport);
}

unsigned short UDPPackage::getUDPLength() const {
    return ntohs(m_udp->m_length);
}

void UDPPackage::setSrcPort(unsigned short src_port) {
    m_udp->m_th_sport = htons(src_port);
}

void UDPPackage::setDstPort(unsigned short dst_port) {
    m_udp->m_th_dport = htons(dst_port);
}

void UDPPackage::setUDPLength(unsigned short length) {
    m_udp->m_length = htons(length);
}

void UDPPackage::recalculateChecksums() {
    PCAPHelper::setIPChecksum(m_ip);
    PCAPHelper::setUDPChecksum(m_ip, m_udp, nullptr);
}

const unsigned char* UDPPackage::getData() const {
    return m_data;
}

unsigned int UDPPackage::getDataLength() const {
    return ntohs(m_udp->m_length) - 8;
}

void UDPPackage::appendData(unsigned char* data, int size) {
    memcpy(&m_package[getDataLength()], (char*)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
    m_udp->m_length = htons(ntohs(m_udp->m_length) + size);
}

unsigned int UDPPackage::getLength() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

}
