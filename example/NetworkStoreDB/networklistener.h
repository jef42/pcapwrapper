#ifndef NETWORKLISTENER_H
#define NETWORKLISTENER_H

#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/packages/udppackage.h>

#include "dbconnection.h"

class NetworkListener : public PCAP::PackageListener<PCAP::TCPPackage>,
                        public PCAP::PackageListener<PCAP::UDPPackage>,
                        public PCAP::PackageListener<PCAP::ICMPPackage>,
                        public PCAP::PackageListener<PCAP::ARPPackage> {
  public:
    NetworkListener(const std::shared_ptr<DBConnection> &db_connection);

    void receive_package(PCAP::TCPPackage package) override;
    void receive_package(PCAP::UDPPackage package) override;
    void receive_package(PCAP::ICMPPackage package) override;
    void receive_package(PCAP::ARPPackage package) override;

  private:
    std::shared_ptr<DBConnection> m_db_connection;
};

#endif
