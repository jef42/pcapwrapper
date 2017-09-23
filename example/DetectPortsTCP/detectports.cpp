#include "detectports.h"

#include <iostream>

using namespace PCAP;

DetectPorts::DetectPorts(PCAP::IpAddress desiredIp) : m_expectedip{desiredIp} {}

void DetectPorts::receivedPackage(PCAP::TCPPackage package) {
    if (package.getSrcIp() == m_expectedip) {
        unsigned char flags = package.getTcpFlags();
        if (flags & 0x02) {
            std::cout << package.getSrcPort() << std::endl;
        }
    }
}
