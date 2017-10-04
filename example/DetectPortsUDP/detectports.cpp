#include "detectports.h"

#include <iostream>
#include <string.h>
#include <string>

using namespace PCAP;

DetectPorts::DetectPorts(PCAP::IpAddress desiredIp) : m_expectedip{desiredIp} {
    reset();
}

void DetectPorts::receive_package(PCAP::ICMPPackage package) {
    if (package.get_src_ip() == m_expectedip) {
        const uchar *data = package.get_package();
        ushort port =
            (((ushort)data[64]) << 0x08) | ((ushort)data[65]);
        m_ports[port] = true;
    }
}

std::vector<int> DetectPorts::get_ports() {
    std::vector<int> result;
    for (int i = 0; i < MAX_PORT; ++i) {
        if (!m_ports[i])
            result.push_back(i);
    }
    reset();
    return result;
}

void DetectPorts::reset() { memset(m_ports, '\0', MAX_PORT); }
