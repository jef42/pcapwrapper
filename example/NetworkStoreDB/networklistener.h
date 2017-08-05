#ifndef NETWORKLISTENER_H
#define NETWORKLISTENER_H

#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/packages/arppackage.h>

#include "dbconnection.h"

class NetworkListener : public PCAP::PackageListener<PCAP::TCPPackage>,
                        public PCAP::PackageListener<PCAP::UDPPackage>,
                        public PCAP::PackageListener<PCAP::ICMPPackage>,
                        public PCAP::PackageListener<PCAP::ARPPackage>
{
public:
    NetworkListener(std::shared_ptr<DBConnection>& db_connection);

    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package) override;
    virtual void receivedPackage(std::unique_ptr<PCAP::UDPPackage> package) override;
    virtual void receivedPackage(std::unique_ptr<PCAP::ICMPPackage> package) override;
    virtual void receivedPackage(std::unique_ptr<PCAP::ARPPackage> package) override;
private:
    std::shared_ptr<DBConnection> m_db_connection;

};

#endif
