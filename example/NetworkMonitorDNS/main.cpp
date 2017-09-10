#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>

#include "dnssessioncontroller.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "1. Interface" << std::endl;
        std::cout << "2. Time" << std::endl;
        std::cout << "3. Ignore Targets" << std::endl;
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface_name);
    int time = std::stoi(argv[2]);

    std::vector<PCAP::IpAddress> ignore_ips;
    std::for_each(&argv[3], &argv[argc], [&ignore_ips](auto ip) { ignore_ips.emplace_back(PCAP::IpAddress(ip)); });
    ignore_ips.emplace_back(local_ip);

    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(interface_name);
    auto session_controller = std::make_shared<DNSSessionController>(std::move(ignore_ips));
    controller->addSessionController(session_controller);
    controller->setFilter("udp dst port 53");
    controller->start();

    std::cout << "NetworkMonitorDNS" << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();
    while (1) {

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(2s);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;
        if (time != -1 && duration.count() > time * 1000) {
            break;
        }
    }

    controller->stop();
    session_controller->finish();
    return 0;
}
