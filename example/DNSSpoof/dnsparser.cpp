#include "dnsparser.h"

#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <pcapwrapper/helpers/helper.h>
#include <stdio.h>

PCAP::sniffethernet create_ethernet(const std::string &src_mac,
                                    const std::string &dst_mac) {
    PCAP::sniffethernet ethernet;
    PCAP::PCAPHelper::setMac(ethernet.m_ether_dhost, dst_mac, 16);
    PCAP::PCAPHelper::setMac(ethernet.m_ether_shost, src_mac, 16);
    ethernet.m_ether_type = htons(0x0800);
    return ethernet;
}

PCAP::sniffip create_ip(const std::string &src_ip, const std::string &dst_ip) {
    PCAP::sniffip ip;
    ip.m_ip_vhl = 0x45;
    ip.m_ip_tos = 0x00;
    ip.m_ip_len = htons(0x0014); // 20
    ip.m_ip_id = htons(0x0000);
    ip.m_ip_off = htons(0x4000);
    ip.m_ip_ttl = 0x40;
    ip.m_ip_p = 0x11;
    ip.m_ip_sum = htons(0x0000);
    PCAP::PCAPHelper::setIp(ip.m_ip_src, src_ip, 10);
    PCAP::PCAPHelper::setIp(ip.m_ip_dst, dst_ip, 10);
    return ip;
}

PCAP::sniffudp create_udp(ushort src_port, ushort dst_port) {
    PCAP::sniffudp udp;
    udp.m_th_sport = htons(src_port);
    udp.m_th_dport = htons(dst_port);
    udp.m_length = htons(0x0008);
    udp.m_checksum = htons(0x0000);
    return udp;
}

DNSParser::DNSParser(const PCAP::uchar *package, int length) {
    memset(m_package, '\0', snap_len);
    memcpy(m_package, package, length);
    m_ethernet = (PCAP::sniffethernet *)&m_package[0];
    m_index = sizeof(*m_ethernet);
    m_ip = (PCAP::sniffip *)&m_package[m_index];
    m_index += sizeof(*m_ip);
    m_udp = (PCAP::sniffudp *)&m_package[m_index];
    m_index += sizeof(*m_udp);
    m_question = (PCAP::sniffdns_question *)&m_package[m_index];
    m_index += sizeof(*m_question);
}

void DNSParser::build() {
    PCAP::PCAPHelper::set_ip_checksum(m_ip);
    PCAP::PCAPHelper::set_udp_checksum(m_ip, m_udp, (PCAP::uchar *)m_question);
}

PCAP::uchar *DNSParser::get_package() const {
    return (PCAP::uchar *)&m_package[0];
}

PCAP::uint DNSParser::get_length() const {
    return ntohs(m_ip->m_ip_len) + size_ethernet;
}
