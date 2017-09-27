#include <iostream>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "detectports.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target_ip\n";
        std::cout << "3. Time(s)\n";
        return -1;
    }

    const std::string interface = argv[1];
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface);
    const auto local_mac = PCAP::PCAPHelper::get_mac(interface);
    const auto target_ip = PCAP::IpAddress(argv[2]);
    const auto target_mac = PCAP::PCAPHelper::get_mac(target_ip, interface);
    int time = std::stoi(argv[3]);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface);
    auto listener = std::make_shared<DetectPorts>(target_ip);

    controller->start();
    controller->add_listener(listener);

    std::cout << "Started " << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (1) {

        for (int port = 1; port <= 65000; ++port) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                {Keys::Key_Eth_Mac_Dst, Option{target_mac}},
                {Keys::Key_Ip_Src, Option{local_ip}},
                {Keys::Key_Ip_Dst, Option{target_ip}},
                {Keys::Key_Src_Port, Option{(unsigned short)45022}},
                {Keys::Key_Dst_Port, Option{(unsigned short)port}}});
            package.recalculate_checksums();
            controller->write(package.get_package(), package.get_length());
        }

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    controller->stop();
}
