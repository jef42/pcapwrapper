#ifndef DETECTTCP_H
#define DETECTTCP_H

#include <string>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>

class DetectTCP : public PCAP::PackageListener<PCAP::TCPPackage>
{
public:
    void receivedPackage(PCAP::TCPPackage package) override;
private:
    
};

#endif // DETECTPORTS_H

