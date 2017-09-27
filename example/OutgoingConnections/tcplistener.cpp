#include "tcplistener.h"

#include <algorithm>
#include <fstream>
#include <iostream>

TcpListener::TcpListener(const PCAP::IpAddress &ip) : m_local_ip{ip} {}

void TcpListener::receive_package(PCAP::TCPPackage package) {
    static std::ofstream file("Tcp.txt");

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
