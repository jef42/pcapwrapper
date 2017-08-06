#ifndef ARPLISTENER_H
#define ARPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "listener.h"

class ARPListener : public PCAP::PackageListener<PCAP::ARPPackage>, public Listener {
public:
    ARPListener(PCAP::IpAddress netmask)
        : Listener{netmask}
    {}

    virtual void receivedPackage(std::unique_ptr<PCAP::ARPPackage> package) override {
        if ((package->getSrcIp() & m_netmask) == m_netmask) {
            inc_count(package->getSrcIp());
        }
        if ((package->getDstIp() & m_netmask) == m_netmask) {
            inc_count(package->getDstIp());
        }
    }
};

#endif
