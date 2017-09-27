#ifndef DETECTNETWORK_H
#define DETECTNETWORK_H

#include <tuple>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/packages/icmppackage.h>

class DetectNetwork : public PCAP::PackageListener<PCAP::ICMPPackage> {
  public:
    void receive_package(PCAP::ICMPPackage package) override;

  private:
    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_packages;
};

#endif
