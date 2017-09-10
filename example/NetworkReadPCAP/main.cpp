#include <iostream>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/interfaces/interfacefile.h>

#include "detecttcp.h"

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "1. Filename\n";
        std::cout << "2. Time(s)\n";
        return -1;
    }

    const std::string filename = argv[1];
    const int time = std::stoi(argv[2]);

    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<DetectTCP>();
    controller->addListener(listener);
    controller->start();

    std::cout << "Started" << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    while (true) {

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;
        if (time != -1 && elapsed.count() > time * 1000)
            break;
    }
    std::cout << "Finished" << std::endl;
    controller->stop();
}
