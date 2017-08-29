#include "ICMPListener.h"

#include <iostream>

ICMPListener::ICMPListener(const PCAP::IpAddress& local_ip)
    : m_local_ip{local_ip}
{

}

void ICMPListener::receivedPackage(PCAP::ICMPPackage package) {
    if (package.getDstIp() == m_local_ip) {
        if (package.getType() == 11) {
            std::cout << "I got one: " << package.getSrcIp() << " I got one" << std::endl;
        }
    }
}
