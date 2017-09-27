#include "maclistener.h"

#include <algorithm>
#include <iostream>
#include <tuple>

void MacListener::receive_package(PCAP::ARPPackage package) {
    auto src_ip = package.get_src_ip();
    auto src_mac = package.get_src_mac();
    auto it =
        std::find_if(m_packages.begin(), m_packages.end(),
                     [&src_ip](auto &a) { return std::get<0>(a) == src_ip; });
    if (it == m_packages.end()) {
        m_packages.emplace_back(std::make_tuple(src_ip, src_mac));
        std::cout << src_ip << " " << src_mac << std::endl;
    }
}
