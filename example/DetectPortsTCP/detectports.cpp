#include "detectports.h"

#include <iostream>

using namespace PCAP;

DetectPorts::DetectPorts(PCAP::IpAddress desiredIp) : m_expectedip{desiredIp} {}

void DetectPorts::receive_package(PCAP::TCPPackage package) {
    if (package.get_src_ip() == m_expectedip) {
        uchar flags = package.get_tcp_flags();
        if (flags & 0x02) {
            std::cout << package.get_src_port() << std::endl;
        }
    }
}
