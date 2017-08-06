#ifndef UDPLISTENER_H
#define UDPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>

#include "listener.h"

class UDPListener : public PCAP::PackageListener<PCAP::UDPPackage>, public Listener {
public:
    UDPListener(const PCAP::IpAddress& netmask)
        : Listener{netmask}
    {}

    virtual void receivedPackage(std::unique_ptr<PCAP::UDPPackage> package) override {
        if ((package->getSrcIp() & m_netmask) == m_netmask) {
            inc_count(package->getSrcIp());
        }
        if ((package->getDstIp() & m_netmask) == m_netmask) {
            inc_count(package->getDstIp());
        }
    }
};

#endif
