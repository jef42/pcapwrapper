#include "../../../include/network/packages/tcppackage.h"

#include <netinet/in.h>
#include <string.h>

#include "../../../include/helpers/helper.h"

namespace PCAP {

TCPPackage::TCPPackage(const unsigned char *p, unsigned int l, bool modify)
    : IPPackage{p, l, modify} {
    m_tcp = (struct snifftcp *)(m_package + size_ethernet + sizeof(sniffip));
    m_data = m_package + size_ethernet + sizeof(sniffip) + sizeof(snifftcp);
}

unsigned short TCPPackage::get_src_port() const {
    return ntohs(m_tcp->m_th_sport);
}

void TCPPackage::set_src_port(unsigned short port) {
    m_tcp->m_th_sport = htons(port);
}

unsigned short TCPPackage::get_dst_port() const {
    return ntohs(m_tcp->m_th_dport);
}

void TCPPackage::set_dst_port(unsigned short port) {
    m_tcp->m_th_dport = htons(port);
}

unsigned char TCPPackage::get_tcp_flags() const { return m_tcp->m_th_flags; }

void TCPPackage::set_tcp_flags(unsigned char flags) { m_tcp->m_th_flags = flags; }

unsigned int TCPPackage::get_seq_nr() const { return ntohl(m_tcp->m_th_seq); }

unsigned int TCPPackage::get_ack_nr() const { return ntohl(m_tcp->m_th_ack); }

unsigned char TCPPackage::get_data_offset() const { return TH_OFF(m_tcp); }

unsigned short TCPPackage::get_window_size() const {
    return ntohs(m_tcp->m_th_win);
}

unsigned short TCPPackage::get_urgent_ptr() const {
    return ntohs(m_tcp->m_th_urp);
}

void TCPPackage::set_seq_nr(unsigned int nr) { m_tcp->m_th_seq = htonl(nr); }

void TCPPackage::set_ack_nr(unsigned int nr) { m_tcp->m_th_ack = htonl(nr); }

void TCPPackage::set_data_offset(unsigned char offset) {
    m_tcp->m_th_offx2 = offset;
}

void TCPPackage::set_window_size(unsigned short size) {
    m_tcp->m_th_win = htons(size);
}

void TCPPackage::set_urgent_ptr(unsigned short ptr) {
    m_tcp->m_th_urp = htons(ptr);
}

void TCPPackage::recalculate_checksums() {
    PCAPHelper::set_ip_checksum(m_ip);
    PCAPHelper::set_tcp_checksum(m_ip, m_tcp, m_data);
}

const unsigned char *TCPPackage::get_data() const {
    if (TH_OFF(m_tcp) > 5)
        return m_data + TH_OFF(m_tcp) * 4 - 20; //? what is 20
    return m_data;
}

unsigned int TCPPackage::get_length() const {
    return sizeof(*m_ethernet) + ntohs(m_ip->m_ip_len);
}

void TCPPackage::append_data(unsigned char *data, int size) {
    memcpy(&m_package[get_length()], (char *)data, size);
    m_ip->m_ip_len = htons(ntohs(m_ip->m_ip_len) + size);
}

unsigned int TCPPackage::get_data_length() const {
    return ntohs(m_ip->m_ip_len) - sizeof(*m_tcp) - sizeof(*m_ip);
}

bool operator==(const TCPPackage &lhs, const TCPPackage &rhs) {
    return static_cast<const IPPackage &>(lhs) ==
               static_cast<const IPPackage &>(rhs) &&
           memcmp(lhs.m_tcp, rhs.m_tcp, sizeof(snifftcp)) == 0;
}

bool operator!=(const TCPPackage &lhs, const TCPPackage &rhs) {
    return !(lhs == rhs);
}
}
