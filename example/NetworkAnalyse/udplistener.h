#ifndef UDPLISTENER_H
#define UDPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>

#include "listener.h"

class UDPListener : public PCAP::PackageListener<PCAP::UDPPackage>,
                    public Listener {
  public:
    UDPListener(const PCAP::IpAddress &netmask) : Listener{netmask} {}

    void receive_package(PCAP::UDPPackage package) override {
        if ((package.get_src_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_src_ip());
        }
        if ((package.get_dst_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_dst_ip());
        }
    }
};

#endif
