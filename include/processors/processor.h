#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "../listeners/packagelistener.h"
#include "../network/packages/arppackage.h"
#include "../network/packages/icmppackage.h"
#include "../network/packages/tcppackage.h"
#include "../network/packages/udppackage.h"
#include "../network/sessions/sessioncontroller.h"
#include "processorpolicy.h"
#include <vector>

namespace PCAP {

class Processor : public ProcessorPolicy {
  public:
    void
    add_listener(const std::shared_ptr<PackageListener<TCPPackage>> &listener);
    void
    add_listener(const std::shared_ptr<PackageListener<ICMPPackage>> &listener);
    void
    add_listener(const std::shared_ptr<PackageListener<UDPPackage>> &listener);
    void
    add_listener(const std::shared_ptr<PackageListener<ARPPackage>> &listener);

    void remove_listener(
        const std::shared_ptr<PackageListener<TCPPackage>> &listener);
    void remove_listener(
        const std::shared_ptr<PackageListener<ICMPPackage>> &listener);
    void remove_listener(
        const std::shared_ptr<PackageListener<UDPPackage>> &listener);
    void remove_listener(
        const std::shared_ptr<PackageListener<ARPPackage>> &listener);

    void add_session_controller(
        const std::shared_ptr<SessionController> &controller);
    void remove_session_controller(
        const std::shared_ptr<SessionController> &controller);

    void clear_all_listeners();
    virtual ~Processor() noexcept = default;

  private:
    template <typename T, typename IT>
    void notify_listeners(IT begin, IT end, const uchar *sniff_package,
                          uint length);

    template <typename T, typename IT> IT remove_weak_ptr(IT begin, IT end);

    template <typename T, typename IT>
    IT remove_weak_ptr(IT begin, IT end,
                       const std::shared_ptr<PackageListener<T>> &listener);

  protected:
    void callback_impl(const uchar *package, const pcap_pkthdr &header);

  private:
    std::vector<std::weak_ptr<PackageListener<TCPPackage>>> m_tcp_listeners;
    std::vector<std::weak_ptr<PackageListener<ICMPPackage>>> m_icmp_listeners;
    std::vector<std::weak_ptr<PackageListener<UDPPackage>>> m_udp_listeners;
    std::vector<std::weak_ptr<PackageListener<ARPPackage>>> m_arp_listeners;
};
}

#endif // LISTENER_H
