#include "../../include/processors/processor.h"

#include <algorithm>
#include <memory>
#include <netinet/in.h>

#include "../../include/performancemeasurement.h"

enum class ETHER_TYPE { APR = 0x0806, IP = 0x0800 };

namespace PCAP {

void Processor::callback_impl(const unsigned char *package,
                              const pcap_pkthdr &header) {
    LOG_BLOCK_D;

    sniffethernet *ethernet = (struct sniffethernet *)(package);
    switch ((ETHER_TYPE)ntohs(ethernet->m_ether_type)) {
    case ETHER_TYPE::APR: {
        notify_listeners<ARPPackage>(m_arp_listeners.begin(),
                                    m_arp_listeners.end(), package, header.len);
        m_arp_listeners.erase(remove_weak_ptr<ARPPackage>(m_arp_listeners.begin(),
                                                        m_arp_listeners.end()),
                              m_arp_listeners.end());
        break;
    }
    case ETHER_TYPE::IP:
        break;
    default:
        return;
    }

    /* define/compute ip header offset */
    sniffip *ip = (struct sniffip *)(package + size_ethernet);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        return;
    }

    switch (ip->m_ip_p) {
    case IPPROTO_TCP: {
        notify_listeners<TCPPackage>(m_tcp_listeners.begin(),
                                    m_tcp_listeners.end(), package, header.len);
        m_tcp_listeners.erase(remove_weak_ptr<TCPPackage>(m_tcp_listeners.begin(),
                                                        m_tcp_listeners.end()),
                              m_tcp_listeners.end());
        break;
    } break;
    case IPPROTO_UDP: {
        notify_listeners<UDPPackage>(m_udp_listeners.begin(),
                                    m_udp_listeners.end(), package, header.len);
        m_udp_listeners.erase(remove_weak_ptr<UDPPackage>(m_udp_listeners.begin(),
                                                        m_udp_listeners.end()),
                              m_udp_listeners.end());
        break;
    }
    case IPPROTO_ICMP: {
        notify_listeners<ICMPPackage>(m_icmp_listeners.begin(),
                                     m_icmp_listeners.end(), package,
                                     header.len);
        m_icmp_listeners.erase(
            remove_weak_ptr<ICMPPackage>(m_icmp_listeners.begin(),
                                       m_icmp_listeners.end()),
            m_icmp_listeners.end());
        break;
    }
    }
}

template <typename T, typename IT>
void Processor::notify_listeners(IT begin, IT end,
                                const unsigned char *sniff_package,
                                unsigned int length) {
    std::for_each(begin, end, [&sniff_package,
                               length](std::weak_ptr<PackageListener<T>> p) {
        std::shared_ptr<PackageListener<T>> listener = p.lock();
        if (listener != nullptr) {
            listener->receive_package(T(sniff_package, length));
        }
    });
}

void Processor::add_listener(
    const std::shared_ptr<PackageListener<TCPPackage>> &listener) {
    m_tcp_listeners.emplace_back(listener);
}
void Processor::add_listener(
    const std::shared_ptr<PackageListener<ICMPPackage>> &listener) {
    m_icmp_listeners.emplace_back(listener);
}
void Processor::add_listener(
    const std::shared_ptr<PackageListener<UDPPackage>> &listener) {
    m_udp_listeners.emplace_back(listener);
}
void Processor::add_listener(
    const std::shared_ptr<PackageListener<ARPPackage>> &listener) {
    m_arp_listeners.emplace_back(listener);
}

void Processor::add_session_controller(
    const std::shared_ptr<SessionController> &controller) {
    m_tcp_listeners.emplace_back(
        static_cast<std::shared_ptr<PackageListener<TCPPackage>>>(controller));
    m_udp_listeners.emplace_back(
        static_cast<std::shared_ptr<PackageListener<UDPPackage>>>(controller));
}

void Processor::remove_listener(
    const std::shared_ptr<PackageListener<TCPPackage>> &listener) {
    m_tcp_listeners.erase(
        remove_weak_ptr(m_tcp_listeners.begin(), m_tcp_listeners.end(), listener),
        m_tcp_listeners.end());
}
void Processor::remove_listener(
    const std::shared_ptr<PackageListener<ICMPPackage>> &listener) {
    m_icmp_listeners.erase(remove_weak_ptr(m_icmp_listeners.begin(),
                                         m_icmp_listeners.end(), listener),
                           m_icmp_listeners.end());
}
void Processor::remove_listener(
    const std::shared_ptr<PackageListener<UDPPackage>> &listener) {
    m_udp_listeners.erase(
        remove_weak_ptr(m_udp_listeners.begin(), m_udp_listeners.end(), listener),
        m_udp_listeners.end());
}
void Processor::remove_listener(
    const std::shared_ptr<PackageListener<ARPPackage>> &listener) {
    m_arp_listeners.erase(
        remove_weak_ptr(m_arp_listeners.begin(), m_arp_listeners.end(), listener),
        m_arp_listeners.end());
}

void Processor::remove_session_controller(
    const std::shared_ptr<SessionController> &controller) {
    m_tcp_listeners.erase(
        remove_weak_ptr(m_tcp_listeners.begin(), m_tcp_listeners.end(),
                      static_cast<std::shared_ptr<PackageListener<TCPPackage>>>(
                          controller)),
        m_tcp_listeners.end());
    m_udp_listeners.erase(
        remove_weak_ptr(m_udp_listeners.begin(), m_udp_listeners.end(),
                      static_cast<std::shared_ptr<PackageListener<UDPPackage>>>(
                          controller)),
        m_udp_listeners.end());
}

void Processor::clear_all_listeners() {
    m_tcp_listeners.clear();
    m_icmp_listeners.clear();
    m_udp_listeners.clear();
    m_arp_listeners.clear();
}

template <typename T, typename IT>
IT Processor::remove_weak_ptr(IT begin, IT end) {
    return std::remove_if(begin, end, [](std::weak_ptr<PackageListener<T>> p) {
        return p.lock() == nullptr;
    });
}

template <typename T, typename IT>
IT Processor::remove_weak_ptr(
    IT begin, IT end, const std::shared_ptr<PackageListener<T>> &listener) {
    return std::remove_if(begin, end,
                          [&listener](std::weak_ptr<PackageListener<T>> p) {
                              return p.lock() == listener;
                          });
}
}
