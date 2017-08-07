#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <vector>

#include "processorpolicy.h"
#include "../listeners/packagelistener.h"
#include "../network/packages/tcppackage.h"
#include "../network/packages/icmppackage.h"
#include "../network/packages/udppackage.h"
#include "../network/packages/arppackage.h"
#include "../network/sessions/sessioncontroller.h"

namespace PCAP {

class Processor : public ProcessorPolicy {
  public:
    void addListener(const std::shared_ptr<PackageListener<TCPPackage>> &listener);
    void addListener(const std::shared_ptr<PackageListener<ICMPPackage>> &listener);
    void addListener(const std::shared_ptr<PackageListener<UDPPackage>> &listener);
    void addListener(const std::shared_ptr<PackageListener<ARPPackage>> &listener);

    void removeListener(const std::shared_ptr<PackageListener<TCPPackage>> &listener);
    void removeListener(const std::shared_ptr<PackageListener<ICMPPackage>> &listener);
    void removeListener(const std::shared_ptr<PackageListener<UDPPackage>> &listener);
    void removeListener(const std::shared_ptr<PackageListener<ARPPackage>> &listener);

    void addSessionController(const std::shared_ptr<SessionController> &controller);
    void removeSessionController(const std::shared_ptr<SessionController> &controller);

    void clearAllListeners();

    virtual ~Processor() {}
  private:
    template <typename T, typename IT>
    void notifyListeners(IT begin, IT end, const unsigned char* sniff_package, unsigned int length);

    template <typename T, typename IT>
    IT removeWeakPtr(IT begin, IT end);

    template <typename T, typename IT>
    IT removeWeakPtr(IT begin, IT end, const std::shared_ptr<PackageListener<T>> &listener);

  protected:
    void callback_impl(const unsigned char *package, const pcap_pkthdr &header);

  private:
    std::vector<std::weak_ptr<PackageListener<TCPPackage>>> m_tcp_listeners;
    std::vector<std::weak_ptr<PackageListener<ICMPPackage>>> m_icmp_listeners;
    std::vector<std::weak_ptr<PackageListener<UDPPackage>>> m_udp_listeners;
    std::vector<std::weak_ptr<PackageListener<ARPPackage>>> m_arp_listeners;
};

}

#endif // LISTENER_H
