#include "detectnetwork.h"

DetectNetwork::DetectNetwork(PCAP::IpAddress target_ip)
    : m_target_ip{target_ip}, m_isUp{false} {}

void DetectNetwork::receive_package(PCAP::ARPPackage package) {
    if (package.get_src_ip() == m_target_ip) {
        m_isUp = true;
    }
}

bool DetectNetwork::isUp() const { return m_isUp; }
