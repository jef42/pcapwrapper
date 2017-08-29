#ifndef DETECTPORTS_H
#define DETECTPORTS_H

#include <string>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

static const int MAX_PORT = 65000;

class DetectPorts : public PCAP::PackageListener<PCAP::ICMPPackage>
{
public:
    DetectPorts(PCAP::IpAddress desiredIp);

    void receivedPackage(PCAP::ICMPPackage package) override;
    std::vector<int> get_ports();

private:
    const PCAP::IpAddress m_expectedip;

    bool m_ports[MAX_PORT];

    void reset();
};

#endif // DETECTPORTS_H

