#include "ICMPListener.h"

#include <iostream>

ICMPListener::ICMPListener(const PCAP::IpAddress &local_ip)
    : m_local_ip{local_ip} {}

void ICMPListener::receive_package(PCAP::ICMPPackage package) {
    if (package.get_dst_ip() == m_local_ip) {
        if (package.get_type() == 11) {
            std::cout << "I got one: " << package.get_src_ip() << " I got one"
                      << std::endl;
        }
    }
}
