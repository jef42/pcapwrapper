#include "udplistener.h"

#include <iostream>
#include <algorithm>
#include <fstream>

UdpListener::UdpListener(const PCAP::IpAddress& ip)
 : m_local_ip{ip}
 {}

void UdpListener::receivedPackage(PCAP::UDPPackage package) {
    static std::ofstream file("Udp.txt");

    if (package.getDstIp() == m_local_ip) {
        IPPort socket(package.getSrcIp(), package.getSrcPort(), package.getDstPort());
        auto it = std::find(m_cache.begin(), m_cache.end(), socket);
        if (it == m_cache.end()) {
            m_cache.push_back(socket);
            file << socket;
        }
    }
}
