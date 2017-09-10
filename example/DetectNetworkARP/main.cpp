#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <chrono>
#include <memory>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

#include "maclistener.h"

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cout << "Wrong usage \n";
        std::cout << "1. Interface\n";
        std::cout << "2. Time(sec)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    auto local_ip = PCAP::PCAPHelper::getIp(interface_name);
    auto net_mask = PCAP::PCAPHelper::getMask(interface_name);
    auto local_mac = PCAP::PCAPHelper::getMac(interface_name);
    auto ips = PCAP::PCAPHelper::getIps(local_ip, net_mask);
    int time = std::stoi(argv[2]);

    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(interface_name);
    auto mac_listener = std::make_shared<MacListener>();
    controller->addListener(mac_listener);
    controller->start();

    std::cout << "Start sending" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    while (1) {
        for (const auto& target_ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
                                                                {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                                                                {Keys::Key_Arp_Mac_Src, Option{local_mac}},
                                                                {Keys::Key_Ip_Src, Option{local_ip}},
                                                                {Keys::Key_Ip_Dst, Option{target_ip}}});
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

    return 0;
}
