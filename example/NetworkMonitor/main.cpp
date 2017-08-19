#include <iostream>
#include <chrono>
#include <thread>
#include <string.h>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "isup.h"
#include "forwardpackage.h"
#include "detectnetwork.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(sec)\n";
        std::cout << "3. Ignore ips\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface_name);
    const auto local_mac = PCAP::PCAPHelper::getMac(interface_name);
    const auto net_mask = PCAP::PCAPHelper::getMask(interface_name);
    const auto router_ip = PCAP::PCAPHelper::getRouterIp(interface_name);
    const auto router_mac = PCAP::PCAPHelper::getMac(router_ip, interface_name);
    auto ips = PCAP::PCAPHelper::getIps(local_ip, net_mask);
    int time = std::stoi(argv[2]);

    std::vector<PCAP::IpAddress> ignore_ips;
    std::for_each(&argv[3], &argv[argc], [&ignore_ips](auto ip) { ignore_ips.emplace_back(PCAP::IpAddress(ip)); });
    ignore_ips.emplace_back(local_ip);
    ips.erase(std::remove_if(std::begin(ips), std::end(ips), [&ignore_ips](auto ip){
        return std::find(std::begin(ignore_ips), std::end(ignore_ips), ip) != std::end(ignore_ips);
    }));

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface_name);
    controller->setFilter("arp");

    auto forward_packages = std::make_shared<ForwardPackage>(local_ip, local_mac, router_ip, router_mac, interface_name);
    auto is_up_detector   = std::make_shared<IsUp>(forward_packages, local_ip, local_mac, interface_name);
    auto network_detector = std::make_shared<DetectNetwork>(forward_packages, is_up_detector, std::move(ignore_ips));

    controller->addListener(network_detector);
    controller->start();

    std::cout << "Start detecting the network" << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        for (const auto& target_ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                            {Keys::Key_Eth_Mac_Src, Option(local_mac)},
                                                            {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                                                            {Keys::Key_Arp_Mac_Src, Option(local_mac)},
                                                            {Keys::Key_Arp_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                                                            {Keys::Key_Arp_Opcode, Option((unsigned char)0x01)},
                                                            {Keys::Key_Ip_Src, Option(local_ip)},
                                                            {Keys::Key_Ip_Dst, Option(target_ip)}});
            controller->write(package.getPackage(), package.getLength());
        }
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(2s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }

    controller->stop();
    is_up_detector->stop();
    forward_packages->stop();
}
