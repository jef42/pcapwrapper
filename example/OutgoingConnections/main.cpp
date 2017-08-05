#include <iostream>
#include <string>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "tcplistener.h"
#include "udplistener.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Wrong number of arguments\n";
        std::cout << "1. Interface name\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface_name);

    auto tcp_listener = std::make_shared<TcpListener>(local_ip);
    auto udp_listener = std::make_shared<UdpListener>(local_ip);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface_name);
    controller->addListener(tcp_listener);
    controller->addListener(udp_listener);

    controller->start();
    std::cout << "Started" << std::endl;
    while(true);
}
