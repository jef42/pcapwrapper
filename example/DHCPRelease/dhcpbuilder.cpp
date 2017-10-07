#include "dhcpbuilder.h"

#include <cstring>
#include <netinet/in.h>
#include <stdio.h>

#include <pcapwrapper/helpers/helper.h>

DHCPBuilder::DHCPBuilder() : m_index{0} {
    memset(m_package, '\0', snap_len);
    m_ethernet = (PCAP::sniffethernet *)&m_package[m_index];
}

void DHCPBuilder::operator<<(PCAP::sniffethernet ethernet) {
    memcpy(m_package, &ethernet, sizeof(ethernet));
    m_index += sizeof(ethernet);
    m_ip = (PCAP::sniffip *)&m_package[m_index];
}

void DHCPBuilder::operator<<(PCAP::sniffip ip) {
    memcpy(&m_package[m_index], &ip, sizeof(ip));
    m_index += sizeof(ip);
    m_udp = (PCAP::sniffudp *)&m_package[m_index];
}

void DHCPBuilder::operator<<(PCAP::sniffudp udp) {
    memcpy(&m_package[m_index], &udp, sizeof(udp));
    m_index += sizeof(udp);
    m_dhcp = (sniffdhcp *)&m_package[m_index];

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(udp));
}

void DHCPBuilder::operator<<(sniffdhcp dhcp) {
    memset(&dhcp.m_legacy, '\0', 192);
    memset(&dhcp.m_chaddr, '\0', 16);
    memcpy(&m_package[m_index], &dhcp, sizeof(dhcp));
    m_index += sizeof(dhcp);

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(dhcp));
    this->m_udp->m_length = htons(ntohs(this->m_udp->m_length) + sizeof(dhcp));
}

void DHCPBuilder::build() {
    if (m_index < 342) {
        m_index = 342;
        this->m_ip->m_ip_len = htons(328);
        this->m_udp->m_length = htons(308);
    }

    PCAP::PCAPHelper::set_ip_checksum(m_ip);
    PCAP::PCAPHelper::set_udp_checksum(m_ip, m_udp, (PCAP::uchar *)m_dhcp);
}

PCAP::uchar *DHCPBuilder::get_package() const {
    return (PCAP::uchar *)&m_package[0];
}

uint DHCPBuilder::get_length() const { return m_index; }
