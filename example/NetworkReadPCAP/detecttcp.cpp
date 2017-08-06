#include "detecttcp.h"

#include <iostream>

void DetectTCP::receivedPackage(std::unique_ptr<PCAP::TCPPackage> package)
{
    std::cout << package->getSrcIp() << ":" << package->getSrcPort() << " -> " << package->getDstIp() << ":" << package->getDstPort() << std::endl;
}
