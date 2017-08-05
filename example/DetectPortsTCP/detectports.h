#ifndef DETECTPORTS_H
#define DETECTPORTS_H

#include <string>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

class DetectPorts : public PCAP::PackageListener<PCAP::TCPPackage>
{
public:
    DetectPorts(PCAP::IpAddress desiredIp);

    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package);

private:
    PCAP::IpAddress m_expectedip;
};

#endif // DETECTPORTS_H

