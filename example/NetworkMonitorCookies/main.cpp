#include <iostream>
#include <memory>
#include <vector>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/processors/processor.h>

#include "cookiesessioncontroller.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    auto const local_ip = PCAP::PCAPHelper::get_ip(interface_name);
    auto const mask = PCAP::PCAPHelper::get_mask(interface_name);
    auto const net = mask & local_ip;

    std::vector<PCAP::IpAddress> ignore_ips;
    std::for_each(&argv[3], &argv[argc], [&ignore_ips](auto ip) {
        ignore_ips.emplace_back(PCAP::IpAddress(ip));
    });
    ignore_ips.emplace_back(PCAP::IpAddress(local_ip));

    int time = std::stoi(argv[2]);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface_name);
    auto cookiesessioncontroller =
        std::make_shared<CookieSessionController>(net, std::move(ignore_ips));
    controller->add_session_controller(cookiesessioncontroller);
    controller->set_filter("tcp dst port 80");
    controller->start();

    std::cout << "NetworkMonitorCookies" << std::endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    while (1) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(2s);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration =
            end_time - start_time;
        if (time != -1 && duration.count() > time * 1000) {
            break;
        }
    }

    controller->stop();
    cookiesessioncontroller->finish();
    return 0;
}