#include "tcplistener.h"

#include <iostream>
#include <algorithm>
#include <fstream>

TcpListener::TcpListener(const PCAP::IpAddress& ip)
: m_local_ip{ip}
{}

void TcpListener::receivedPackage(PCAP::TCPPackage package) {
    static std::ofstream file("Tcp.txt");

    if (package.getDstIp() == m_local_ip) {
        IPPort socket(package.getSrcIp(), package.getSrcPort(), package.getDstPort());
        auto it = std::find(m_cache.begin(), m_cache.end(), socket);
        if (it == m_cache.end()) {
            m_cache.push_back(socket);
            file << socket;
        }
    }
}
