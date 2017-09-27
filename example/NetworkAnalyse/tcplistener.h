#ifndef TCPLISTENER_H
#define TCPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>

#include "listener.h"
#include <iostream>

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>,
                    public Listener {
  public:
    TCPListener(const PCAP::IpAddress &netmask) : Listener{netmask} {}

    void receive_package(PCAP::TCPPackage package) override {
        if ((package.get_src_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_src_ip());
        }
        if ((package.get_dst_ip() & m_netmask) == m_netmask) {
            inc_count(package.get_dst_ip());
        }
    }
};

#endif
