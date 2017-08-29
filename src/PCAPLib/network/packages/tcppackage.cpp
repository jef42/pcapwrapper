#include "tcppackage.h"

#include <netinet/in.h>
#include <string.h>

#include "../../helpers/helper.h"

namespace PCAP {

TCPPackage::TCPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_tcp = (struct snifftcp*)(m_package + size_ethernet + 5*4);
    if (TH_OFF(m_tcp) > 5) { //if there is optional data
        m_tcp_opt = (struct snifftcpopt*)(m_package + size_ethernet + 5 * 4 + sizeof(*m_tcp)); //tcp_opt can be also over the data, is it max 40
        m_data = m_package + size_ethernet + 5 * 4 + sizeof(*m_tcp) + TH_OFF(m_tcp) * 4 - 20; //
    } else {
        m_data = m_package + size_ethernet + 5 * 4 + sizeof(*m_tcp);
    }
}

unsigned short TCPPackage::getSrcPort() const {
    return ntohs(m_tcp->m_th_sport);
}

void TCPPackage::setSrcPort(unsigned short port) {
    m_tcp->m_th_sport = htons(port);
}

unsigned short TCPPackage::getDstPort() const {
    return ntohs(m_tcp->m_th_dport);
}

void TCPPackage::setDstPort(unsigned short port) {
    m_tcp->m_th_dport = htons(port);
}

unsigned char TCPPackage::getFlags() const {
    return m_tcp->m_th_flags;
}

void TCPPackage::setFlags(unsigned char flags) {
    m_tcp->m_th_flags = flags;
}

unsigned int TCPPackage::getSeqNr() const {
    return ntohl(m_tcp->m_th_seq);
}

unsigned int TCPPackage::getAckNr() const {
    return ntohl(m_tcp->m_th_ack);
}

unsigned char TCPPackage::getDataOffset() const {
    return TH_OFF(m_tcp);
}

unsigned short TCPPackage::getWindowSize() const {
    return ntohs(m_tcp->m_th_win);
}

unsigned short TCPPackage::getUrgentPtr() const {
    return ntohs(m_tcp->m_th_urp);
}

void TCPPackage::setSeqNr(unsigned int nr) {
    m_tcp->m_th_seq = htonl(nr);
}

void TCPPackage::setAckNr(unsigned int nr) {
    m_tcp->m_th_ack = htonl(nr);
}

void TCPPackage::setDataOffset(unsigned char offset) {
    m_tcp->m_th_offx2 = offset;
}

void TCPPackage::setWindowSize(unsigned short size) {
    m_tcp->m_th_win = htons(size);
}

void TCPPackage::setUrgentPtr(unsigned short ptr) {
    m_tcp->m_th_urp = htons(ptr);
}

void TCPPackage::recalculateChecksums() {
    PCAPHelper::setIPChecksum(m_ip);
    PCAPHelper::setTCPChecksum(m_ip, m_tcp, m_tcp_opt, m_data);
}

const unsigned char* TCPPackage::getData() const {
    return m_data;
}

unsigned int TCPPackage::getLength() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

void TCPPackage::appendData(unsigned char* data, int size) {
    memcpy(&m_package[getDataLength()], (char*)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
}

unsigned int TCPPackage::getDataLength() const {
    return ntohs(m_ip->m_ip_len) - ((IP_HL(m_ip) + TH_OFF(m_tcp)) * 4);
}

}
