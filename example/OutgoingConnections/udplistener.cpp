#include "udplistener.h"

#include <algorithm>
#include <fstream>
#include <iostream>

UdpListener::UdpListener(const PCAP::IpAddress &ip) : m_local_ip{ip} {}

void UdpListener::receive_package(PCAP::UDPPackage package) {
    static std::ofstream file("Udp.txt");

    if (package.get_dst_ip() == m_local_ip) {
        IPPort socket(package.get_src_ip(), package.get_src_port(),
                      package.get_dst_port());
        auto it = std::find(m_cache.begin(), m_cache.end(), socket);
        if (it == m_cache.end()) {
            m_cache.push_back(socket);
            file << socket;
        }
    }
}
