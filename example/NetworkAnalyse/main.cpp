#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/processors/processor.h>

#include "arplistener.h"
#include "icmplistener.h"
#include "tcplistener.h"
#include "udplistener.h"

using namespace std::chrono_literals;

void print_result(
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> &tcp_packages,
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> &udp_packages,
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> &arp_packages,
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> &icmp_packages,
    unsigned long sum) {
    for (auto &t : tcp_packages) {
        std::cout << "Ip: " << t.first << "\n";
        std::cout << "TCP: " << t.second << " " << (double)t.second * 100 / sum
                  << "%\n";

        {
            auto it_udp =
                std::find_if(udp_packages.begin(), udp_packages.end(),
                             [&t](auto u) { return t.first == u.first; });
            if (it_udp != udp_packages.end()) {
                std::cout << "UDP: " << it_udp->second << " "
                          << (double)it_udp->second * 100 / sum << "%\n";
            }
        }

        {
            auto it_icmp =
                std::find_if(icmp_packages.begin(), icmp_packages.end(),
                             [&t](auto i) { return t.first == i.first; });
            if (it_icmp != icmp_packages.end()) {
                std::cout << "ICMP: " << it_icmp->second << " "
                          << (double)it_icmp->second * 100 / sum << "%\n";
            }
        }

        {
            auto it_arp =
                std::find_if(arp_packages.begin(), arp_packages.end(),
                             [&t](auto a) { return t.first == a.first; });
            if (it_arp != arp_packages.end()) {
                std::cout << "ARP: " << it_arp->second << " "
                          << (double)it_arp->second * 100 / sum << "%\n";
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    auto netmask = PCAP::PCAPHelper::get_mask(interface_name);
    auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface_name);
    auto tcp_listener = std::make_shared<TCPListener>(netmask & local_ip);
    auto udp_listener = std::make_shared<UDPListener>(netmask & local_ip);
    auto icmp_listener = std::make_shared<ICMPListener>(netmask & local_ip);
    auto arp_listener = std::make_shared<ARPListener>(netmask & local_ip);
    int time = std::stoi(argv[2]);

    controller->add_listener(tcp_listener);
    controller->add_listener(udp_listener);
    controller->add_listener(icmp_listener);
    controller->add_listener(arp_listener);
    controller->start();

    auto start = std::chrono::high_resolution_clock::now();
    unsigned long total = 0;
    while (true) {
        std::this_thread::sleep_for(1s);

        auto nr_tcp = tcp_listener->get_count();
        auto nr_udp = udp_listener->get_count();
        auto nr_icmp = icmp_listener->get_count();
        auto nr_arp = arp_listener->get_count();
        total += nr_tcp.size() + nr_udp.size() + nr_icmp.size() + nr_arp.size();

        std::cout << "Total: " << total << "\n";
        print_result(nr_tcp, nr_udp, nr_arp, nr_icmp, total);

        std::cout << "\033[H\033[J";

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    controller->stop();
}
