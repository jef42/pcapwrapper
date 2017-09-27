#ifndef DETECTPORTS_H
#define DETECTPORTS_H

#include <string>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/tcppackage.h>

class DetectPorts : public PCAP::PackageListener<PCAP::TCPPackage> {
  public:
    DetectPorts(PCAP::IpAddress desiredIp);

    void receive_package(PCAP::TCPPackage package) override;

  private:
    PCAP::IpAddress m_expectedip;
};

#endif // DETECTPORTS_H
