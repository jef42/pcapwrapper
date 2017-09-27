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

    virtual void receive_package(PCAP::ICMPPackage package) override {
        if ((package.get_src_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_src_ip());
        }
        if ((package.get_dst_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_dst_ip());
        }
    }
};

#endif
