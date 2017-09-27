#ifndef ICMPLISTENER_H
#define ICMPLISTENER_H

#include <string>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/icmppackage.h>

class ICMPListener : public PCAP::PackageListener<PCAP::ICMPPackage> {
  public:
    ICMPListener(const PCAP::IpAddress &local_ip);
    void receive_package(PCAP::ICMPPackage package) override;

  private:
    PCAP::IpAddress m_local_ip;
};

#endif
