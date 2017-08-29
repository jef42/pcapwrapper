#include "ippackage.h"

#include <netinet/in.h>
#include <cstring>

namespace PCAP {

IPPackage::IPPackage(const unsigned char* p, unsigned int l, bool modify)
    : EthernetPackage{p, l, modify}
{
    m_ip = (sniffip*)(m_package + size_ethernet);
}

IpAddress IPPackage::getSrcIp() const {
    return IpAddress(m_ip->m_ip_src);
}

IpAddress IPPackage::getDstIp() const {
    return IpAddress(m_ip->m_ip_dst);
}

unsigned char IPPackage::getVHL() const {
    return m_ip->m_ip_vhl;
}

unsigned char IPPackage::getTOS() const {
    return m_ip->m_ip_tos;
}

unsigned short IPPackage::getTotalLength() const {
    return ntohs(m_ip->m_ip_len);
}

unsigned short IPPackage::getID() const {
    return ntohs(m_ip->m_ip_id);
}

unsigned char IPPackage::getFlags() const {
    return ntohs(m_ip->m_ip_off) >> 13;
}

unsigned short IPPackage::getFragmentOffset() const {
    return ntohs(m_ip->m_ip_off) & IP_OFFMASK;
}

unsigned char IPPackage::getTTL() const {
    return m_ip->m_ip_ttl;
}

unsigned char IPPackage::getProtocol() const {
    return m_ip->m_ip_p;
}

void IPPackage::setDstIp(IpAddress ip) {
    memcpy(m_ip->m_ip_dst, ip.data(), ip_addr_len);
}

void IPPackage::setSrcIp(IpAddress ip) {
    memcpy(m_ip->m_ip_src, ip.data(), ip_addr_len);
}

void IPPackage::setVHL(unsigned char value) {
    m_ip->m_ip_vhl = value;
}

void IPPackage::setTOS(unsigned char value) {
    m_ip->m_ip_tos = value;
}

void IPPackage::setTotalLength(unsigned short length) {
    m_ip->m_ip_len = htons(length);
}

void IPPackage::setID(unsigned short id) {
    m_ip->m_ip_id = htons(id);
}

void IPPackage::setFlags(unsigned char flags) {
    m_ip->m_ip_off |= (htons(flags) << 13);
}

void IPPackage::setFragmentOffset(unsigned short fragment) {
    m_ip->m_ip_off |= (htons(fragment) & IP_OFFMASK);
}

void IPPackage::setTTL(unsigned char ttl) {
    m_ip->m_ip_ttl = ttl;
}

void IPPackage::setProtocol(unsigned char protocol) {
    m_ip->m_ip_p = protocol;
}

}
