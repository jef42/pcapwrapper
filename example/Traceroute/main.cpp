#include <iostream>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>
#include <pcapwrapper/processors/processor.h>

#include "ICMPListener.h"
#include "TCPListener.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target\n";
        return -1;
    }

    std::string interface_name = argv[1];
    const auto target_ip = PCAP::IpAddress(argv[2]);
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);
    const auto local_mac = PCAP::PCAPHelper::get_mac(interface_name);

    const auto router_ip = PCAP::PCAPHelper::get_router_ip(interface_name);
    const auto router_mac =
        PCAP::PCAPHelper::get_mac(router_ip, interface_name);

    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface_name);
    auto icmp_listener = std::make_shared<ICMPListener>(local_ip);
    auto tcp_listener = std::make_shared<TCPListener>(target_ip);

    controller->add_listener(icmp_listener);
    controller->add_listener(tcp_listener);

    controller->start();

    std::cout << "Started" << std::endl;

    PCAP::uchar i = 0;
    while (!tcp_listener->isFinished()) {

        using namespace PCAP::PCAPBuilder;
        auto package = PCAP::PCAPBuilder::make_tcp(std::map<Keys, Option>{
            {Keys::Key_Eth_Mac_Src, Option{local_mac}},
            {Keys::Key_Eth_Mac_Dst, Option{router_mac}},
            {Keys::Key_Ip_Src, Option{local_ip}},
            {Keys::Key_Ip_Dst, Option{target_ip}},
            {Keys::Key_Src_Port, Option{(ushort)45022}},
            {Keys::Key_Dst_Port, Option{(ushort)80}},
            {Keys::Key_Tcp_SeqNr, Option{(uint)i * 3323}},
            {Keys::Key_Ip_TTL, Option{(PCAP::uchar)i++}}});
        package.recalculate_checksums();
        controller->write(package.get_package(), package.get_length());

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);
    }
}
