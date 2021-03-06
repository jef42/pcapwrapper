#include "detectnetwork.h"

#include <algorithm>

DetectNetwork::DetectNetwork(
    const std::shared_ptr<ForwardPackage> &forward_package,
    std::vector<PCAP::IpAddress> &&ignore_ips)
    : m_forward_package{forward_package}, m_ignore_ips{ignore_ips} {}

void DetectNetwork::receive_package(PCAP::ARPPackage package) {
    auto src_ip = package.get_src_ip();
    auto src_mac = package.get_src_mac();
    if (src_ip.to_long() == 0)
        return;
    if (std::find(m_ignore_ips.begin(), m_ignore_ips.end(), src_ip) ==
        m_ignore_ips.end()) {
        m_forward_package->new_client(src_ip, src_mac);
    }
}
