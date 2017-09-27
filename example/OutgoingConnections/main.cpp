#include <iostream>
#include <memory>
#include <string>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/processors/processor.h>

#include "tcplistener.h"
#include "udplistener.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "Wrong number of arguments\n";
        std::cout << "1. Interface name\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);

    auto tcp_listener = std::make_shared<TcpListener>(local_ip);
    auto udp_listener = std::make_shared<UdpListener>(local_ip);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface_name);
    controller->add_listener(tcp_listener);
    controller->add_listener(udp_listener);

    controller->start();
    std::cout << "Started" << std::endl;
    while (true)
        ;
}
