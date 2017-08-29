#include "detectnetwork.h"

#include <algorithm>

DetectNetwork::DetectNetwork(const std::shared_ptr<ForwardPackage> &forward_package, 
                             const std::shared_ptr<IsUp> &is_up, std::vector<PCAP::IpAddress> &&ignore_ips)
  : m_forward_package{forward_package}
  , m_is_up{is_up}
  , m_ignore_ips{ignore_ips}
{

}

void DetectNetwork::receivedPackage(PCAP::ARPPackage package)
{
    auto src_ip = package.getSrcIp();
    auto src_mac = package.getSrcMac();
    if (std::find(m_ignore_ips.begin(), m_ignore_ips.end(), src_ip) == m_ignore_ips.end())
    {
        m_forward_package->newClient(src_ip, src_mac);
        m_is_up->addTarget(src_ip, src_mac);
    }
}
