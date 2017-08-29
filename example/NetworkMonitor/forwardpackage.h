#ifndef FORWARDPACKAGE_H
#define FORWARDPACKAGE_H

#include <vector>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

struct NetworkClient {
    NetworkClient(PCAP::IpAddress ip, PCAP::MacAddress mac)
        : m_ip{ip}
        , m_mac{mac}
    {}
    friend bool operator==(const NetworkClient &lhs, const NetworkClient &rhs) {
        return lhs.m_ip == rhs.m_ip && lhs.m_mac == rhs.m_mac;
    }
    PCAP::IpAddress m_ip;
    PCAP::MacAddress m_mac;
    bool m_running = true;
};

class ForwardPackage {
public:
    ForwardPackage(PCAP::IpAddress local_ip,
                   PCAP::MacAddress local_mac,
                   PCAP::IpAddress router_ip,
                   PCAP::MacAddress router_mac,
                   const std::string& interface_name);
    void new_client(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac);
    void stop();

private:
    void clients_receivers();
    void working_function();

    PCAP::IpAddress m_local_ip;
    PCAP::MacAddress m_local_mac;
    PCAP::IpAddress m_router_ip;
    PCAP::MacAddress m_router_mac;
    std::string m_interface_name;
    bool m_stop;

    std::future<void> m_future_clients;
    std::future<void> m_future_working;


    std::mutex m_mutex;
    std::vector<NetworkClient> m_new_clients;
    std::vector<NetworkClient> m_existing_clients;
};

#endif
