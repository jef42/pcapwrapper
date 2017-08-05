#include "detectports.h"

#include <iostream>

using namespace PCAP;

DetectPorts::DetectPorts(PCAP::IpAddress desiredIp)
    : m_expectedip{desiredIp}
{

}

void DetectPorts::receivedPackage(std::unique_ptr<PCAP::TCPPackage> package)
{
    if (package->getSrcIp() == m_expectedip) {
        unsigned char flags = package->getFlags();
        if ( flags & 0x02 ) {
            std::cout << package->getSrcPort() << std::endl;
        }
    }
}

