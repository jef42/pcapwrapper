#ifndef TCPLISTENER_H
#define TCPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>

#include "listener.h"
#include <iostream>

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>, public Listener {
public:
    TCPListener(const PCAP::IpAddress& netmask)
        : Listener{netmask}
    {}

    void receivedPackage(PCAP::TCPPackage package) override {
        if ((package.getSrcIp() & m_netmask) == m_netmask) {
            inc_count(package.getSrcIp());
        }
        if ((package.getDstIp() & m_netmask) == m_netmask) {
            inc_count(package.getDstIp());
        }
    }
};

#endif
