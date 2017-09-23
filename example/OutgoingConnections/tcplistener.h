#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

#include <string>
#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/tcppackage.h>

#include "ipport.h"

class TcpListener : public PCAP::PackageListener<PCAP::TCPPackage> {
  public:
    TcpListener(const PCAP::IpAddress &ip);
    void receivedPackage(PCAP::TCPPackage package) override;

  private:
    PCAP::IpAddress m_local_ip;
    std::vector<IPPort> m_cache;
};

#endif
