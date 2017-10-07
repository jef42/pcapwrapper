#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "detectnetwork.h"
#include "forwardpackage.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "1. Interface\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);
    const auto local_mac = PCAP::PCAPHelper::get_mac(interface_name);
    const auto net_mask = PCAP::PCAPHelper::get_mask(interface_name);
    const auto router_ip = PCAP::PCAPHelper::get_router_ip(interface_name);
    const auto router_mac =
        PCAP::PCAPHelper::get_mac(router_ip, interface_name);
    auto ips = PCAP::PCAPHelper::get_ips(local_ip, net_mask);

    std::vector<PCAP::IpAddress> ignore_ips;
    std::for_each(&argv[2], &argv[argc], [&ignore_ips](auto ip) {
        ignore_ips.emplace_back(PCAP::IpAddress(ip));
    });
    ignore_ips.emplace_back(local_ip);
    ips.erase(
        std::remove_if(std::begin(ips), std::end(ips), [&ignore_ips](auto ip) {
            return std::find(std::begin(ignore_ips), std::end(ignore_ips),
                             ip) != std::end(ignore_ips);
        }));

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface_name);
    controller->set_filter("arp");

    auto forward_packages = std::make_shared<ForwardPackage>(
        local_ip, local_mac, router_ip, router_mac, interface_name);
    auto network_detector = std::make_shared<DetectNetwork>(
        forward_packages, std::move(ignore_ips));

    controller->add_listener(network_detector);
    controller->start();

    std::cout << "Start detecting the network" << std::endl;

    while (true) {
        for (const auto &target_ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_arp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, Option(local_mac)},
                {Keys::Key_Eth_Mac_Dst,
                 Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                {Keys::Key_Arp_Mac_Src, Option(local_mac)},
                {Keys::Key_Arp_Mac_Dst,
                 Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                {Keys::Key_Arp_Opcode, Option((PCAP::uchar)0x01)},
                {Keys::Key_Ip_Src, Option(local_ip)},
                {Keys::Key_Ip_Dst, Option(target_ip)}});
            controller->write(package.get_package(), package.get_length());
        }
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10s);
    }
    controller->stop();
    forward_packages->stop();
}
