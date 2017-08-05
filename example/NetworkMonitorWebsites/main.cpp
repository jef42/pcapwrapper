#include <iostream>
#include <vector>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>

#include "httpsessioncontroller.h"

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::getIp(interface_name);
    const auto mask = PCAP::PCAPHelper::getMask(interface_name);
    const auto net = mask & local_ip;

    std::vector<PCAP::IpAddress> ignore_ips;
    std::for_each(&argv[3], &argv[argc], [&ignore_ips](auto ip) { ignore_ips.emplace_back(PCAP::IpAddress(ip)); });
    ignore_ips.emplace_back(local_ip);

    int time = std::stoi(argv[2]);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface_name);
    auto httpsessioncontroller = std::make_shared<HTTPSessionController>(net, std::move(ignore_ips));
    controller->addSessionController(httpsessioncontroller);
    controller->setFilter("tcp dst port 80");
    controller->start();

    std::cout << "NetworkMonitorWebsites" << std::endl;
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
    httpsessioncontroller->finish();
    return 0;
}
