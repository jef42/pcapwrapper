#include "detectnetwork.h"

#include <iostream>
#include <algorithm>

void DetectNetwork::receivedPackage(std::unique_ptr<PCAP::ICMPPackage> package)
{
    auto src_ip = package->getSrcIp();
    auto src_mac = package->getSrcMac();
    auto it = std::find_if(m_packages.begin(), m_packages.end(),
                           [&src_ip](auto& a)
                           {
                                return std::get<0>(a) == src_ip;
                           });
    if (it == m_packages.end())
    {
        m_packages.emplace_back(std::make_tuple(src_ip, src_mac));
        std::cout << src_ip << " " <<  src_mac << std::endl;
    }
}
