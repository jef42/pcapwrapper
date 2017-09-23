#include <iostream>
#include <memory>
#include <string.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "detectnetwork.h"

int main(int argc, char *argv[]) {
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
    auto ips = PCAP::PCAPHelper::getIps(local_ip,
                                        PCAP::PCAPHelper::getMask(interface));
    const int time = std::stoi(argv[2]);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface);
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
                {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                {Keys::Key_Eth_Mac_Dst, Option{router_mac}},
                {Keys::Key_Ip_Src, Option{local_ip}},
                {Keys::Key_Ip_Dst, Option{ip}},
                {Keys::Key_Src_Port, Option{(unsigned short)45022}},
                {Keys::Key_Dst_Port, Option{(unsigned short)45022}}});
            package.recalculateChecksums();
            controller->write(package.getPackage(), package.getLength());
        }

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(3s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }

    controller->stop();
}
