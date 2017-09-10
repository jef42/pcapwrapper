#include "dnssessioncontroller.h"

#include <netinet/in.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <cstring>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/processors/processorempty.h>
#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>

#include "dnsbuilder.h"
#include "dnsframe.h"
#include "dnsparser.h"

static const int QUERIES = 12;

DNSSessionController::DNSSessionController(const PCAP::MacAddress& local_mac, const PCAP::IpAddress& local_ip, const PCAP::IpAddress &router_ip,
                                           const PCAP::MacAddress& router_mac, const std::string& interface_name, bool force_all)
 : m_local_mac{local_mac}
 , m_local_ip{local_ip}
 , m_interface_name{interface_name}
 , m_router_ip{router_ip}
 , m_router_mac{router_mac}
 , m_force_all{force_all}
{
    read_websites();
}

void DNSSessionController::read_websites() {
    std::ifstream file("block_websites");
    std::string line;
    while (std::getline(file, line)) {
        auto pos = line.find(' ');
        std::string website = line.substr(0, pos);
        std::string ip = line.substr(pos+1, std::string::npos);
        m_block_websites.emplace_back(website, ip);
    }
}

std::string DNSSessionController::is_block_website(const std::string& data) {
    for (auto& entry : m_block_websites) {
        if (data.find(entry.m_website) != std::string::npos) {
            return entry.m_ip;
        }
    }
    return "0.0.0.0";
}

void DNSSessionController::receivedPackage(PCAP::UDPPackage package) {

    std::string data = std::string((char*) &(package.getData()[QUERIES+1]));

    if (m_force_all) {
        send_reply(package, m_local_ip.to_string());
    }
    else {
        auto ip = is_block_website(data);
        if (ip != "0.0.0.0") {
            send_reply(package, ip);
        }
        else {
            forward_question(package);
        }
    }
}

void DNSSessionController::send_reply(PCAP::UDPPackage package, const std::string& ip) {
    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(m_interface_name);

    DNSBuilder builder;
    builder << create_ethernet(package.getDstMac().to_string(), package.getSrcMac().to_string());
    builder << create_ip(package.getDstIp().to_string(), package.getSrcIp().to_string());
    builder << create_udp(package.getDstPort(), package.getSrcPort());
    builder << create_dns_question(1, package.getData(), QUERIES);
    builder << create_dns_query(&package.getData()[QUERIES]);
    builder << create_dns_answer(ip);
    builder.build();
    controller->write(builder.getPackage(), builder.getLength());
}

void DNSSessionController::forward_question(PCAP::UDPPackage package) {
    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(m_interface_name);

    DNSParser parser(package.getPackage(), package.getLength());
    memcpy(parser.m_ethernet->m_ether_shost, m_local_mac.data(), 6);
    memcpy(parser.m_ethernet->m_ether_dhost, m_router_mac.data(), 6);
    parser.build();
    controller->write(parser.getPackage(), parser.getLength());
}
