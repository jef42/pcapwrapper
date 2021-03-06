#ifndef TCPLISTENER_H
#define TCPLISTENER_H

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/tcppackage.h>

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage> {
  public:
    TCPListener(const PCAP::IpAddress &target_ip);
    void receive_package(PCAP::TCPPackage package) override;
    bool isFinished() const;

  private:
    PCAP::IpAddress m_target_ip;
    bool m_finished;
};

#endif
