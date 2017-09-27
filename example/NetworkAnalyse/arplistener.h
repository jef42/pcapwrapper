#ifndef ARPLISTENER_H
#define ARPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/arppackage.h>

#include "listener.h"

class ARPListener : public PCAP::PackageListener<PCAP::ARPPackage>,
                    public Listener {
  public:
    ARPListener(PCAP::IpAddress netmask) : Listener{netmask} {}

    void receive_package(PCAP::ARPPackage package) override {
        if ((package.get_src_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_src_ip());
        }
        if ((package.get_dst_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_dst_ip());
        }
    }
};

#endif
