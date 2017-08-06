#include <iostream>

#include <string>
#include <algorithm>
#include <sstream>
#include <memory>
#include <string.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

#include "detectnetwork.h"

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Wrong nr of parameters\n";
        std::cout << "1. Interface wlan\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    auto ip = PCAP::PCAPHelper::getIp(argv[1]);
    const auto mask = PCAP::PCAPHelper::getMask(argv[1]);
    const auto mac = PCAP::PCAPHelper::getMac(argv[1]);
    const auto ips = PCAP::PCAPHelper::getIps(ip, mask);
    std::string interface = argv[1];
    int time = std::stoi(argv[2]);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface);
    auto sniffer = std::make_shared<DetectNetwork>();
    controller->addListener(sniffer);

    controller->setFilter("icmp");
    controller->start();

    std::cout << "Started" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (1)
    {
        for(const auto& dest_ip : ips)
        {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, mac},
                {Keys::Key_Eth_Mac_Dst, PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))},
                {Keys::Key_Ip_Src, ip},
                {Keys::Key_Ip_Dst, dest_ip},
                {Keys::Key_Icmp_Code, (unsigned char)0x00},
                {Keys::Key_Icmp_Type, (unsigned char)0x08}
            });
            package.recalculateChecksums();
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
}