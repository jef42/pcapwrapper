#ifndef DETECTNETWORK_H
#define DETECTNETWORK_H

#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>

class DetectNetwork : public PCAP::PackageListener<PCAP::ARPPackage>
{
public:
    DetectNetwork(PCAP::IpAddress target_ip);
    void receivedPackage(PCAP::ARPPackage package) override;
    bool isUp() const;
private:
    const PCAP::IpAddress m_target_ip;
    bool m_isUp;
};

#endif // DETECTMAP_H
