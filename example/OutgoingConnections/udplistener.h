#ifndef UDP_LISTENER_H
#define UDP_LISTENER_H

#include <string>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "ipport.h"

class UdpListener : public PCAP::PackageListener<PCAP::UDPPackage> {
public:
    UdpListener(const PCAP::IpAddress& ip);
    virtual void receivedPackage(std::unique_ptr<PCAP::UDPPackage> package) override;
private:
    PCAP::IpAddress m_local_ip;
    std::vector<IPPort> m_cache;
};


#endif
