#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <fstream>

#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "dnssessioncontroller.h"
#include "dnsentry.h"

void save_file(const std::string& file_name, const std::vector<DNSEntry>& entries) {
    std::ofstream stream(file_name);
    std::for_each(std::begin(entries), std::end(entries), [&stream](auto& entry){ stream << entry;});
    stream.close();
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cout << "1. Interface\n";
        std::cout << "2. Targets\n";
        return -1;
    }

    std::map<PCAP::IpAddress,std::vector<DNSEntry>> websites;

    auto interface = argv[1];

    std::vector<PCAP::IpAddress> targets_ip;
    std::for_each(&argv[2], &argv[argc], [&targets_ip](auto ip){ targets_ip.emplace_back(PCAP::IpAddress(ip)); });

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(interface);
    auto sessioncontroller = std::make_shared<DNSSessionController>(targets_ip);
    controller->addSessionController(sessioncontroller);

    controller->setFilter("dns");
    controller->start();

    std::cout << "Started" << std::endl;
    while (1) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(5s);

        //update entries
        auto tmp = sessioncontroller->get_websites();
        for (auto& target : tmp) {
            for (auto& website : target.second) {
                auto it = std::find(websites[target.first].begin(), websites[target.first].end(), website);
                if (it == websites[target.first].end()) {
                    websites[target.first].push_back(website);
                    std::cout << website << std::endl;
                }
                else {
                    it->update(website.get_time());
                }
            }
         }

        //write to file
        std::for_each(std::begin(websites), std::end(websites), [](auto entry){  save_file(entry.first.to_string(), entry.second); });
    }

    std::cout << "Finished" << std::endl;
    controller->stop();
}
