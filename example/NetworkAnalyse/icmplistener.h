#ifndef ICMPLISTENER_H
#define ICMPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "listener.h"

class ICMPListener : public PCAP::PackageListener<PCAP::ICMPPackage>, public Listener {
public:
    ICMPListener(const PCAP::IpAddress& ip)
        : Listener{ip}
    {}

    virtual void receivedPackage(std::unique_ptr<PCAP::ICMPPackage> package) override {
        if (package->getSrcIp() == m_ip || package->getDstIp() == m_ip)
            inc_count();
    }
};

#endif