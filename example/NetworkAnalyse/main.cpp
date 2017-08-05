#include <iostream>
#include <thread>
#include <chrono>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "arplistener.h"
#include "icmplistener.h"
#include "tcplistener.h"
#include "udplistener.h"

using namespace std::chrono_literals;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target\n";
        std::cout << "3. Time(s)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto target_ip = PCAP::IpAddress(argv[2]);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface_name);
    auto tcp_listener = std::make_shared<TCPListener>(target_ip);
    auto udp_listener = std::make_shared<UDPListener>(target_ip);
    auto icmp_listener = std::make_shared<ICMPListener>(target_ip);
    auto arp_listener = std::make_shared<ARPListener>(target_ip);
    int time = std::stoi(argv[3]);

    controller->addListener(tcp_listener);
    controller->addListener(udp_listener);
    controller->addListener(icmp_listener);
    controller->addListener(arp_listener);
    controller->start();

    auto start = std::chrono::high_resolution_clock::now();
    while (true) {
        unsigned long nr_tcp = tcp_listener->get_count();
        unsigned long nr_udp = udp_listener->get_count();
        unsigned long nr_icmp = icmp_listener->get_count();
        unsigned long nr_arp = arp_listener->get_count();
        unsigned long sum = nr_tcp + nr_udp + nr_icmp + nr_arp;

        std::this_thread::sleep_for(1s);
        std::cout << "TCP: " << nr_tcp << " " << (double)nr_tcp*100/sum << "%\n";
        std::cout << "UDP: " << nr_udp << " " << (double)nr_udp*100/sum << "%\n";
        std::cout << "ICMP: " << nr_icmp << " " << (double)nr_icmp*100/sum << "%\n";
        std::cout << "ARP: " << nr_arp << " " << (double)nr_arp*100/sum << "%\n";

        std::cout << "\033[H\033[J";

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    controller->stop();
}
