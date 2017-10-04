#include <iostream>

#include <algorithm>
#include <memory>
#include <sstream>
#include <string>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "detectnetwork.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "Wrong nr of parameters\n";
        std::cout << "1. Interface wlan\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    auto ip = PCAP::PCAPHelper::get_ip(argv[1]);
    const auto mask = PCAP::PCAPHelper::get_mask(argv[1]);
    const auto mac = PCAP::PCAPHelper::get_mac(argv[1]);
    const auto ips = PCAP::PCAPHelper::get_ips(ip, mask);
    std::string interface = argv[1];
    int time = std::stoi(argv[2]);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface);
    auto sniffer = std::make_shared<DetectNetwork>();
    controller->add_listener(sniffer);

    controller->set_filter("icmp");
    controller->start();

    std::cout << "Started" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        for (const auto &dest_ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, Option{mac}},
                {Keys::Key_Eth_Mac_Dst,
                 Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                {Keys::Key_Ip_Src, Option{ip}},
                {Keys::Key_Ip_Dst, Option{dest_ip}},
                {Keys::Key_Icmp_Code, Option{(uchar)0x00}},
                {Keys::Key_Icmp_Type, Option{(uchar)0x08}}});
            package.recalculate_checksums();
            controller->write(package.get_package(), package.get_length());
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
