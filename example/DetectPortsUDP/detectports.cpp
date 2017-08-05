#include "detectports.h"

#include <iostream>
#include <string>
#include <string.h>

using namespace PCAP;

DetectPorts::DetectPorts(PCAP::IpAddress desiredIp)
    : m_expectedip{desiredIp}
{
    reset();
}

void DetectPorts::receivedPackage(std::unique_ptr<PCAP::ICMPPackage> package)
{
    if (package->getSrcIp() == m_expectedip) {
        const unsigned char* data = package->getPackage();
        unsigned short port = (((unsigned short)data[64]) << 0x08) | ((unsigned short)data[65]);
        m_ports[port] = true;
    }
}

std::vector<int> DetectPorts::get_ports()
{
    std::vector<int> result;
    for (int i = 0; i < MAX_PORT; ++i) {
        if (!m_ports[i])
            result.push_back(i);
    }
    reset();
    return result;
}

void DetectPorts::reset()
{
    memset(m_ports, '\0', MAX_PORT);
}

