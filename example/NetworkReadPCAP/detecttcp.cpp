#include "detecttcp.h"

#include <iostream>

void DetectTCP::receive_package(PCAP::TCPPackage package) {
    std::cout << package.get_src_ip() << ":" << package.get_src_port() << " -> "
              << package.get_dst_ip() << ":" << package.get_dst_port() << std::endl;
}
