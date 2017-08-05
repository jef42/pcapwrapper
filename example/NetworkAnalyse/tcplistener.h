#ifndef TCPLISTENER_H
#define TCPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>

#include "listener.h"

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>, public Listener {
public:
    TCPListener(const PCAP::IpAddress& ip)
        : Listener{ip}
    {}

    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package) override {
        if (package->getSrcIp() == m_ip || package->getDstIp() == m_ip)
            inc_count();
    }
};

#endif
