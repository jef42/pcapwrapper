#include <iostream>
#include <string>
#include <chrono>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processorqueue.h>

#include "networklistener.h"
#include "dbconnection.h"

int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. DBname\n";
        std::cout << "3. Time(sec)\n";
        return -1;
    }

    std::string net_interface = argv[1];
    std::string db_name = argv[2];
    int time = std::stoi(argv[3]);

    auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(net_interface);
    auto db_connection = std::make_shared<DBConnection>(db_name);
    auto listener = std::make_shared<NetworkListener>(db_connection);
    controller->addListener(static_cast<std::shared_ptr<PCAP::PackageListener<PCAP::TCPPackage>>>(listener));
    controller->addListener(static_cast<std::shared_ptr<PCAP::PackageListener<PCAP::UDPPackage>>>(listener));
    controller->addListener(static_cast<std::shared_ptr<PCAP::PackageListener<PCAP::ICMPPackage>>>(listener));
    controller->addListener(static_cast<std::shared_ptr<PCAP::PackageListener<PCAP::ARPPackage>>>(listener));

    controller->start();

    std::cout << "Started" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while(1) {
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    controller->stop();
}
