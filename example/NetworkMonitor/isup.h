#ifndef ISUP_H
#define ISUP_H

#include <memory>
#include <vector>
#include <future>

#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "forwardpackage.h"

class IsUp {
public:
    IsUp(const std::shared_ptr<ForwardPackage>& forward_package, PCAP::IpAddress local_ip, PCAP::MacAddress local_mac, const std::string& interface);
    ~IsUp();

    void addTarget(PCAP::IpAddress ip, PCAP::MacAddress mac);
    void stop();

private:
    std::mutex m_targets_mtx;
    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_targets;

    std::mutex m_received_targets_mtx;
    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_received_targets;

    std::shared_ptr<ForwardPackage> m_forward_package;
    PCAP::IpAddress m_local_ip;
    PCAP::MacAddress m_local_mac;
    std::string m_interface;

    bool m_stop_worker;
    std::future<void> m_worker;
    void worker_impl();
};

#endif // ISUP_H
