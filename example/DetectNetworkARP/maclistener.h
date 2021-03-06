#ifndef MACLISTENER_H
#define MACLISTENER_H

#include <string>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/packages/arppackage.h>

class MacListener : public PCAP::PackageListener<PCAP::ARPPackage> {
  public:
    void receive_package(PCAP::ARPPackage package) override;

  private:
    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_packages;
};

#endif
