#include <iostream>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "detectports.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cout << "Wrong nr of parameters\n";
        std::cout << "1. Interface\n";
        std::cout << "2. TargetIp\n";
        std::cout << "3. Time(s)\n";
        std::cout << std::endl;
        return -1;
    }

    std::string interface = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface);
    const auto local_mac = PCAP::PCAPHelper::getMac(interface);
    const auto target_ip = PCAP::IpAddress(argv[2]);
    const auto target_mac = PCAP::PCAPHelper::getMac(target_ip, interface);
    int time = std::stoi(argv[3]);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface);
    auto sniffer = std::make_shared<DetectPorts>(target_ip);
    controller->addListener(sniffer);

    controller->setFilter("tcp");
    controller->start();

    std::cout << "DetectPortsTCP" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        for (int i = 1; i < 0xFFFF; ++i) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_tcp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                {Keys::Key_Eth_Mac_Dst, Option{target_mac}},
                {Keys::Key_Ip_Src, Option{local_ip}},
                {Keys::Key_Ip_Dst, Option{target_ip}},
                {Keys::Key_Src_Port, Option{(unsigned short)45022}},
                {Keys::Key_Dst_Port, Option{(unsigned short)i}},
                {Keys::Key_Tcp_SeqNr, Option{(unsigned int)i * 3323}}});
            package.recalculateChecksums();
            controller->write(package.getPackage(), package.getLength());
        }

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(6s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    controller->stop();
}
