#include "dnsbuilder.h"

#include <stdio.h>
#include <netinet/in.h>
#include <cstring>

#include <pcapwrapper/helpers/helper.h>

bool setIp(unsigned char* ip, const std::string& ip_value, int base) {
    std::array<unsigned char, ip_addr_len> array;
    bool successful = PCAP::PCAPHelper::split_string<unsigned char, ip_addr_len>(ip_value, '.', array, base);
    if (successful) {
        memcpy(ip, array.data(), ip_addr_len);
    }
    return successful;
}

bool setMac(unsigned char* addr, const std::string& ethernet_value, int base) {
    std::array<unsigned char, ethernet_addr_len> array;
    bool sucessful = PCAP::PCAPHelper::split_string<unsigned char,ethernet_addr_len>(ethernet_value, ':', array, base);
    if (sucessful) {
        memcpy(addr, array.data(), ethernet_addr_len);
    }
    return sucessful;
}

DNSBuilder::DNSBuilder()
    : m_index{0}
{
    memset(m_package, '\0', snap_len);
}

void DNSBuilder::operator << (PCAP::sniffethernet ethernet) {
    memcpy(m_package, &ethernet, sizeof(ethernet));
    m_index += sizeof(ethernet);
    m_ip = (PCAP::sniffip*)&m_package[m_index];
}

void DNSBuilder::operator <<(PCAP::sniffip ip) {
    memcpy(&m_package[m_index], &ip, sizeof(ip));
    m_index += sizeof(ip);
    m_udp = (PCAP::sniffudp*)&m_package[m_index];
}

void DNSBuilder::operator <<(PCAP::sniffudp udp) {
    memcpy(&m_package[m_index], &udp, sizeof(udp));
    m_index += sizeof(udp);
    m_question = (sniffdns_question*)&m_package[m_index];

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(udp));
}

void DNSBuilder::operator <<(sniffdns_question question) {
    memcpy(&m_package[m_index], &question, sizeof(question));
    m_index += sizeof(question);
    m_query = (sniffdns_query*)&m_package[m_index];

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(question));
    this->m_udp->m_length = htons(ntohs(this->m_udp->m_length) + sizeof(question));
}

void DNSBuilder::operator <<(sniffdns_query query) {
    memcpy(&m_package[m_index], query.m_query, strlen((char*)query.m_query));
    m_index += strlen((char*)query.m_query) + 1;
    memcpy(&m_package[m_index], &query.m_type, 2);
    m_index += 2;
    memcpy(&m_package[m_index], &query.m_class, 2);
    m_index += 2;
    m_answer = (sniffdns_answer*)&m_package[m_index];

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + strlen((char*)query.m_query) + 5);
    this->m_udp->m_length = htons(ntohs(this->m_udp->m_length) + strlen((char*)query.m_query) + 5);
}

void DNSBuilder::operator <<(sniffdns_answer answer) {
    memcpy(&m_package[m_index], &answer, sizeof(answer));
    m_index += sizeof(answer);

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(answer));
    this->m_udp->m_length = htons(ntohs(this->m_udp->m_length) + sizeof(answer));
}

void DNSBuilder::build() {
    PCAP::PCAPHelper::setIPChecksum(m_ip);
    PCAP::PCAPHelper::setUDPChecksum(m_ip, m_udp, (unsigned char*)m_question);
}

unsigned char* DNSBuilder::getPackage() const {
    return (unsigned char*)&m_package[0];
}

unsigned int DNSBuilder::getLength() const {
    return m_index;
}

PCAP::sniffethernet create_ethernet(const std::string& src_mac, const std::string& dst_mac) {
    PCAP::sniffethernet ethernet;
    setMac(ethernet.m_ether_dhost, dst_mac, 16);
    setMac(ethernet.m_ether_shost, src_mac, 16);
    ethernet.m_ether_type = htons(0x0800);
    return ethernet;
}

PCAP::sniffip create_ip(const std::string& src_ip, const std::string& dst_ip) {
    PCAP::sniffip ip;
    ip.m_ip_vhl = 0x45;
    ip.m_ip_tos = 0x00;
    ip.m_ip_len = htons(0x0014); //20
    ip.m_ip_id = htons(0x0000);
    ip.m_ip_off = htons(0x4000);
    ip.m_ip_ttl = 0x40;
    ip.m_ip_p = 0x11;
    ip.m_ip_sum = htons(0x0000);
    setIp(ip.m_ip_src, src_ip, 10);
    setIp(ip.m_ip_dst, dst_ip, 10);
    return ip;
}

PCAP::sniffudp create_udp(unsigned short src_port, unsigned short dst_port) {
    PCAP::sniffudp udp;
    udp.m_th_sport = htons(src_port);
    udp.m_th_dport = htons(dst_port);
    udp.m_length = htons(0x0008);
    udp.m_checksum = htons(0x0000);
    return udp;
}

sniffdns_question create_dns_question(unsigned short answers, const unsigned char* data, unsigned short size) {
    sniffdns_question question;
    memcpy(&question, data, size);
    question.m_flags = htons(0x8180);
    question.m_answers = htons(answers);
    return question;
}

sniffdns_query create_dns_query(const unsigned char* website) {
    sniffdns_query query;
    query.m_query = (unsigned char*)website;
    query.m_type = htons(0x0001);
    query.m_class = htons(0x0001);
    return query;
}

sniffdns_answer create_dns_answer(const std::string& spoof_ip) {
    sniffdns_answer answer;
    answer.m_name = htons(0xc00c);
    answer.m_type = htons(0x0001);
    answer.m_class = htons(0x0001);
    answer.m_time_to_live[0] = 0x00;
    answer.m_time_to_live[1] = 0x00;
    answer.m_time_to_live[2] = 0x00;
    answer.m_time_to_live[3] = 0x18;
    answer.data_length = htons(0x0004);
    setIp(answer.m_address, spoof_ip, 10);
    return answer;
}

