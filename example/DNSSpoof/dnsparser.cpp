#include "dnsparser.h"

#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdio.h>

#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/helper.h>

DNSParser::DNSParser(const PCAP::uchar *package, int length) {
    memset(m_package, '\0', snap_len);
    memcpy(m_package, package, length);
    m_ethernet = (PCAP::sniffethernet *)&m_package[0];
    m_index = sizeof(*m_ethernet);
    m_ip = (PCAP::sniffip *)&m_package[m_index];
    m_index += sizeof(*m_ip);
    m_udp = (PCAP::sniffudp *)&m_package[m_index];
    m_index += sizeof(*m_udp);
    m_question = (sniffdns_question *)&m_package[m_index];
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
