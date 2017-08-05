#ifndef MACLISTENER_H
#define MACLISTENER_H

#include "../../listeners/packagelistener.h"
#include "../../network/packages/arppackage.h"
#include "../../network/addresses/ipaddress.h"
#include "../../network/addresses/macaddress.h"

namespace PCAP {
namespace PCAPHelper {

class MacListener : public PCAP::PackageListener<PCAP::ARPPackage>
{
public:
    MacListener(const PCAP::IpAddress& ip);
    virtual void receivedPackage(std::unique_ptr<PCAP::ARPPackage> package) override;

    PCAP::MacAddress getMac() const;
private:
    PCAP::IpAddress m_ip;
    PCAP::MacAddress m_result;
    bool m_founded;
};

}
}

#endif // MACLISTENER_H
