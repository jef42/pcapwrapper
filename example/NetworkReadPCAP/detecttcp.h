#ifndef DETECTTCP_H
#define DETECTTCP_H

#include <string>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>

class DetectTCP : public PCAP::PackageListener<PCAP::TCPPackage>
{
public:
    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package);
private:
    
};

#endif // DETECTPORTS_H

