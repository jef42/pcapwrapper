#ifndef MACLISTENER_H
#define MACLISTENER_H

#include "../../listeners/packagelistener.h"
#include "../../network/addresses/ipaddress.h"
#include "../../network/addresses/macaddress.h"
#include "../../network/packages/arppackage.h"

namespace PCAP {
namespace PCAPHelper {

class MacListener : public PCAP::PackageListener<PCAP::ARPPackage> {
  public:
    explicit MacListener(const PCAP::IpAddress &ip);
    virtual void receive_package(PCAP::ARPPackage package) override;

    PCAP::MacAddress get_mac() const noexcept;

  private:
    PCAP::IpAddress m_ip;
    PCAP::MacAddress m_result;
    bool m_founded;
};
}
}

#endif // MACLISTENER_H
