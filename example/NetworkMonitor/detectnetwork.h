#ifndef DETECTNETWORK_H
#define DETECTNETWORK_H

#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>

#include "forwardpackage.h"
#include "isup.h"

class DetectNetwork : public PCAP::PackageListener<PCAP::ARPPackage>
{
public:
    DetectNetwork(const std::shared_ptr<ForwardPackage> &forward_package, 
                  const std::shared_ptr<IsUp> &is_up, std::vector<PCAP::IpAddress>&& ignore_ips);

    virtual void receivedPackage(std::unique_ptr<PCAP::ARPPackage> package) override;
private:
    std::shared_ptr<ForwardPackage> m_forward_package;
    std::shared_ptr<IsUp> m_is_up;
    std::vector<PCAP::IpAddress> m_ignore_ips;
};

#endif
