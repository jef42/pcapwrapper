#include <iostream>
#include <iostream>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processorsave.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cout << "1. Interface\n";
        std::cout << "2. Filename\n";
        std::cout << "3. Time(s)\n";
        return -1;
    }

    const std::string interface = argv[1];
    const std::string filename = argv[2];
    const int time = std::stoi(argv[3]);

    auto controller = std::make_shared<
        PCAP::Controller<PCAP::Interface, PCAP::ProcessorSave>>(interface);
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
    controller->save(filename);
    controller->stop();
}
