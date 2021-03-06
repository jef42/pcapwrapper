#include <future>
#include <iostream>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processorempty.h>
#include <pcapwrapper/processors/processorpolicy.h>

static std::string interface_name;

class SendProcessor : public PCAP::ProcessorPolicy {
  private:
    void callback_impl(const PCAP::uchar *package,
                       const pcap_pkthdr &header) override {
        static auto controller = std::make_shared<
            PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(
            interface_name);
        controller->write(package, header.len);
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Filename\n";
        return -1;
    }

    interface_name = argv[1];
    const std::string filename = argv[2];

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::InterfaceFile, SendProcessor>>(
            filename);
    controller->start();

    std::promise<void>().get_future().wait();
    controller->stop();
    std::cout << "Here" << std::endl;
    return 0;
}