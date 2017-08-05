#include <iostream>
#include <string.h>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

#include "detectnetwork.h"

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(sec)\n";
        return -1;
    }

    const std::string interface = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface);
    const auto local_mac = PCAP::PCAPHelper::getMac(interface);
    const auto router_ip = PCAP::PCAPHelper::getRouterIp(interface);
    const auto router_mac = PCAP::PCAPHelper::getMac(router_ip, interface);
    auto ips = PCAP::PCAPHelper::getIps(local_ip, PCAP::PCAPHelper::getMask(interface));
    const int time = std::stoi(argv[2]);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface);
    auto listener = std::make_shared<DetectNetwork>();
    controller->addListener(listener);

    controller->setFilter("icmp");
    controller->start();

    std::cout << "Started " << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        for (const auto ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{
                    {Keys::Key_Eth_Mac_Src, local_mac},
                    {Keys::Key_Eth_Mac_Dst, router_mac},
                    {Keys::Key_Ip_Src, local_ip},
                    {Keys::Key_Ip_Dst, ip},
                    {Keys::Key_Src_Port, (unsigned short)45022},
                    {Keys::Key_Dst_Port, (unsigned short)45022}
            });
            package.recalculateChecksums();
            controller->write(package.getPackage(), package.getLength());
        }

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(3s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end-start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }

    controller->stop();
}
