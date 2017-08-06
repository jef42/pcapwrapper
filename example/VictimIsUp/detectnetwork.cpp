#include "detectnetwork.h"

#include <iostream>


DetectNetwork::DetectNetwork(PCAP::IpAddress target_ip)
 : m_target_ip{target_ip}
 , m_isUp{false}
 {}

void DetectNetwork::receivedPackage(std::unique_ptr<PCAP::ARPPackage> package)
{
    if (package->getSrcIp() == m_target_ip)
    {
      m_isUp = true;
    }
}

bool DetectNetwork::isUp() const
{
  return m_isUp;
}