#ifndef DETECTNETWORK_H
#define DETECTNETWORK_H

#include <vector>
#include <tuple>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>

class DetectNetwork : public PCAP::PackageListener<PCAP::ICMPPackage>
{
public:
    void receivedPackage(PCAP::ICMPPackage package) override;
private:
    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_packages;
};

#endif
