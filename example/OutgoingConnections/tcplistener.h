#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

#include <string>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "ipport.h"

class TcpListener : public PCAP::PackageListener<PCAP::TCPPackage> {
public:
    TcpListener(const PCAP::IpAddress& ip);
    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package) override;
private:
    PCAP::IpAddress m_local_ip;
    std::vector<IPPort> m_cache;
};

#endif
