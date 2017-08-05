#ifndef FORWARDPACKAGE_H
#define FORWARDPACKAGE_H

#include <vector>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

struct ThreadFlags {
    ThreadFlags(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac)
        : m_target_ip{target_ip}
        , m_target_mac{target_mac}
    {}

    PCAP::IpAddress m_target_ip;
    PCAP::MacAddress m_target_mac;
    bool m_stop = false;
};

class ForwardPackage {
public:
    ForwardPackage(PCAP::IpAddress local_ip,
                   PCAP::MacAddress local_mac,
                   PCAP::IpAddress router_ip,
                   PCAP::MacAddress router_mac,
                   const std::string& interface_name);
    void newClient(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);
    void stopClient(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);
    void stop();

private:
    void workingFunction(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);
    bool is_stop(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);
    auto get_flags(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);

    PCAP::IpAddress m_local_ip;
    PCAP::MacAddress m_local_mac;
    PCAP::IpAddress m_router_ip;
    PCAP::MacAddress m_router_mac;
    std::string m_interface_name;

    std::vector<std::tuple<PCAP::IpAddress, PCAP::MacAddress>> m_packages;

    std::mutex m_mutex;
    std::vector<std::unique_ptr<std::thread>> m_threads;
    std::vector<ThreadFlags> m_flags;
};

#endif
