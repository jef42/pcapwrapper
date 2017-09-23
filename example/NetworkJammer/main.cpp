#include <iostream>
#include <memory>
#include <string>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/processors/processorempty.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(s)\n";
        return 0;
    }

    std::string net_interf = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(argv[1]);
    const auto local_mac = PCAP::PCAPHelper::getMac(argv[1]);
    int time = std::stoi(argv[2]);

    const auto router_ip = PCAP::PCAPHelper::getRouterIp(net_interf);
    const auto router_mac = PCAP::PCAPHelper::getMac(router_ip, net_interf);

    auto controller = std::make_shared<
        PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(net_interf);
    controller->start();

    std::cout << "Started" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        using namespace PCAP::PCAPBuilder;
        auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
            {Keys::Key_Eth_Mac_Src, Option{local_mac}},
            {Keys::Key_Eth_Mac_Dst, Option{router_mac}},
            {Keys::Key_Ip_Src, Option{local_ip}},
            {Keys::Key_Ip_Dst, Option{router_ip}},
            {Keys::Key_Icmp_Code, Option{(unsigned char)0x00}},
            {Keys::Key_Icmp_Type, Option{(unsigned char)0x08}}});
        package.recalculateChecksums();
        controller->write(package.getPackage(), package.getLength());

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }

    controller->stop();
}
