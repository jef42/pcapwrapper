#include "TCPListener.h"

#include <iostream>

TCPListener::TCPListener(const PCAP::IpAddress &local_ip)
    : m_target_ip{local_ip}, m_finished{false} {}

void TCPListener::receive_package(PCAP::TCPPackage package) {
    if (package.get_src_ip() == m_target_ip) {
        std::cout << "We finished" << std::endl;
        m_finished = true;
    }
}

bool TCPListener::isFinished() const { return m_finished; }
