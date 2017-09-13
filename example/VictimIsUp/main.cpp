#include <iostream>
#include <memory>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "detectnetwork.h"

int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target ip\n";
        std::cout << "3. Time(s)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface_name);
    const auto local_mac = PCAP::PCAPHelper::getMac(interface_name);
    const auto target_ip = PCAP::IpAddress(argv[2]);
    int time = std::stoi(argv[3]);

    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(interface_name);
    auto listener = std::make_shared<DetectNetwork>(target_ip);
    controller->addListener(listener);
    controller->start();

    std::cout << "Started" << std::endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    while (!listener->isUp()) {
        using namespace PCAP::PCAPBuilder;
        auto package = PCAP::PCAPBuilder::make_arp(std::map<Keys, Option>{
                                                            {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                                                            {Keys::Key_Arp_Mac_Src, Option{local_mac}},
                                                            {Keys::Key_Arp_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                                                            {Keys::Key_Ip_Src, Option{local_ip}},
                                                            {Keys::Key_Ip_Dst, Option{target_ip}}});
        controller->write(package.getPackage(), package.getLength());

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;
        if (time != -1 && duration.count() > time * 1000)
            return -1;
    }
    controller->stop();
    return 0;
}
