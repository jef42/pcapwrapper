#ifndef ICMPLISTENER_H
#define ICMPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/icmppackage.h>

#include "listener.h"

class ICMPListener : public PCAP::PackageListener<PCAP::ICMPPackage>,
                     public Listener {
  public:
    ICMPListener(const PCAP::IpAddress &netmask) : Listener{netmask} {}

    virtual void receivedPackage(PCAP::ICMPPackage package) override {
        if ((package.getSrcIp() & m_netmask) == m_netmask) {
            inc_count(package.getSrcIp());
        }
        if ((package.getDstIp() & m_netmask) == m_netmask) {
            inc_count(package.getDstIp());
        }
    }
};

#endif
