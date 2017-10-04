#include <iostream>
#include <memory>

#include <pcapwrapper/helpers/helper.h>
#include

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "1. Interface\n";
        return;
    }

    const std::string interface_name = argv[1];
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);
    const auto local_mac = PCAP::PCAPHelper::get_mac(interface_name);
    const auto router_ip = PCAP::PCAPHelper::get_router_ip(interface_name);
    const auto router_mac = PCAP::PCAPHelper::get_mac(router_ip, interface_name);
    auto ips = PCAP::PCAPHelper::get_ips(local_ip, net_mask);

    ips.remove(std::remove_if(std::begin(ips), std::end(ips),
                              [&local_ip](auto ip) { return local_ip == ip; },
                              std::end(ips)));

    auto controller = std::make_shared < PCAP::Controller < PCAP::Interface,
         PCAP;:Processor>>(interface_name);
    auto network_listener =
        std::make_shared<NetworkListener>(controller, local_ip);
    auto tcp_port_listener =
        std::make_shared<TCPPortListener>(controller, local_ip);
    auto udp_port_listener =
        std::make_shared<UDPPortListener>(controller, local_ip);
    controller->add_listener(network_listener);
    controller->add_listener(tcp_port_listener);
    controller->add_listener(udp_port_listener);

    controller->start();
    while (true) {
        for (const auto &target_ip : ips) {
            using namespace PCAP::PCAPBuilder;
            auto package = PCAP::PCAPBuilder::make_arp(std::map<Keys, Option>{
                {Keys::Key_Eth_Mac_Src, Option(local_mac)},
                {Keys::Key_Eth_Mac_Dst,
                 Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                {Keys::Key_Arp_Mac_Src, Option(local_mac)},
                {Keys::Key_Arp_Mac_Dst,
                 Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                {Keys::Key_Arp_Opcode, Option((uchar)0x01)},
                {Keys::Key_Ip_Src, Option(local_ip)},
                {Keys::Key_Ip_Dst, Option(target_ip)}});
            controller->write(package.get_package(), package.get_length());
        }
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10s);
    }

    controller->stop();
}