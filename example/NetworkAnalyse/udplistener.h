#ifndef UDPLISTENER_H
#define UDPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>

#include "listener.h"

class UDPListener : public PCAP::PackageListener<PCAP::UDPPackage>, public Listener {
public:
    UDPListener(const PCAP::IpAddress& ip)
        : Listener{ip}
    {}

    virtual void receivedPackage(std::unique_ptr<PCAP::UDPPackage> package) override {
        if (package->getSrcIp() == m_ip || package->getDstIp() == m_ip)
            inc_count();
    }
};

#endif
