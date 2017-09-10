#include <iostream>
#include <future>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/helpers/helper.h>

#include "dnssessioncontroller.h"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target\n";
        std::cout << "3. 1/0\n";
        return 0;
    }

    std::string interface_name = argv[1];
    const auto target_ip = PCAP::IpAddress(argv[2]);
    bool force = std::stoi(argv[3]);

    const auto router_ip = PCAP::PCAPHelper::getRouterIp(interface_name);
    const auto router_mac = PCAP::PCAPHelper::getMac(router_ip, interface_name);
    const auto local_mac = PCAP::PCAPHelper::getMac(interface_name);
    const auto local_ip  = PCAP::PCAPHelper::getIp(interface_name);

    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(interface_name);
    auto listener = std::make_shared<DNSSessionController>(local_mac, local_ip, router_ip, router_mac, interface_name, force);
    controller->addListener(listener);
    controller->setFilter("src host " + target_ip.to_string() + "&& udp dst port 53");
    controller->start();

    std::promise<void>().get_future().wait();
}
