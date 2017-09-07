#include "../../../include/network/builders/builder.h"

#include <netinet/in.h>

#include "../../../include/network/addresses/macaddress.h"
#include "../../../include/network/addresses/ipaddress.h"

namespace PCAP {
namespace PCAPBuilder {

static unsigned char package_buffer[snap_len] = {};

void set_ethernet(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Eth_Mac_Src) {
            package.setSrcMac(option.second.m_value_mac);
        }
        if (option.first == Keys::Key_Eth_Mac_Dst) {
            package.setDstMac(option.second.m_value_mac);
        }
    }
}

void set_ip(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Ip_Src) {
            package.setSrcIp(option.second.m_value_ip);
        }
        if (option.first == Keys::Key_Ip_Dst) {
            package.setDstIp(option.second.m_value_ip);
        }
        if (option.first == Keys::Key_Ip_TTL) {
            package.setTTL(option.second.m_value_char);
        }
        if (option.first == Keys::Key_Ip_Flags) {
            package.setFlags(option.second.m_value_char);
        }
        if (option.first == Keys::Key_Ip_Id) {
            package.setID(option.second.m_value_short);
        }
        if (option.first == Keys::Key_Ip_Length) {
            package.setTotalLength(option.second.m_value_short);
        }
    }
}

void set_udp(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Udp_Length) {
            package.setUDPLength(option.second.m_value_short);
        }
        if (option.first == Keys::Key_Src_Port) {
            package.setSrcPort(option.second.m_value_short);
        }
        if (option.first == Keys::Key_Dst_Port) {
            package.setDstPort(option.second.m_value_short);
        }
    }
}

void set_icmp(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Icmp_Type) {
            package.setType(option.second.m_value_char);
        }
        if (option.first == Keys::Key_Icmp_Code) {
            package.setCode(option.second.m_value_char);
        }
    }
}

void set_tcp(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Src_Port) {
            package.setSrcPort(option.second.m_value_short);
        }
        if (option.first == Keys::Key_Dst_Port) {
            package.setDstPort(option.second.m_value_short);
        }
        if (option.first == Keys::Key_Tcp_SeqNr) {
            package.setSeqNr(option.second.m_value_int);
        }
        if (option.first == Keys::Key_Tcp_AckNr) {
            package.setAckNr(option.second.m_value_int);
        }
        if (option.first == Keys::Key_Tcp_Flags) {
            package.setFlags(option.second.m_value_char);
        }
    }
}

void set_arp(auto& package, std::map<Keys, Option>& options) {
    for (auto& option : options) {
        if (option.first == Keys::Key_Arp_Mac_Src) {
            package.setSrcArpMac(option.second.m_value_mac);
        }
        if (option.first == Keys::Key_Arp_Mac_Dst) {
            package.setDstArpMac(option.second.m_value_mac);
        }
        if (option.first == Keys::Key_Arp_Opcode) {
            package.setOpcode(option.second.m_value_char);
        }
        if (option.first == Keys::Key_Ip_Src) {
            package.setSrcIp(option.second.m_value_ip);
        }
        if (option.first == Keys::Key_Ip_Dst) {
            package.setDstIp(option.second.m_value_ip);
        }
    }
}

PCAP::ARPPackage make_apr(std::map<Keys, Option> options) {

    PCAP::ARPPackage package(package_buffer, snap_len, true);
    package.setSrcMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setDstMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setEtherType(0x0806);
    package.setHardwareType(0x01);
    package.setProtocol(0x0800);
    package.setHardwareLength(0x06);
    package.setProtocolLength(0x04);
    package.setOpcode(0x01);
    package.setSrcArpMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setSrcIp(IpAddress("255.255.255.255"));
    package.setDstArpMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setDstIp(IpAddress("255.255.255.255"));

    set_ethernet(package, options);
    set_arp(package, options);

    return package;
}

PCAP::UDPPackage make_udp(std::map<Keys, Option> options) {

    PCAP::UDPPackage package(package_buffer, snap_len, true);
    package.setSrcMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setDstMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setEtherType(0x0800);
    package.setVHL(0x45);
    package.setTOS(0x0);
    package.setTotalLength(0x001c);
    package.setID(0x1000);
    package.setFlags(0x0);
    package.setFragmentOffset(0x0);
    package.setTTL(0x64);
    package.setProtocol(0x11);
    package.setSrcIp(IpAddress("255.255.255.255"));
    package.setDstIp(IpAddress("255.255.255.255"));
    package.setSrcPort(1);
    package.setDstPort(1);
    package.setUDPLength(0x0008);

    set_ethernet(package, options);
    set_ip(package, options);
    set_udp(package, options);

    return package;
}

ICMPPackage make_icmp(std::map<Keys, Option> options) {
    PCAP::ICMPPackage package(package_buffer, snap_len, true);
    package.setSrcMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setDstMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setEtherType(0x0800);
    package.setVHL(0x45);
    package.setTOS(0x0);
    package.setTotalLength(0x001c);
    package.setID(0x1000);
    package.setFlags(0x0);
    package.setFragmentOffset(0x0);
    package.setTTL(0x64);
    package.setProtocol(0x01);
    package.setSrcIp(IpAddress("255.255.255.255"));
    package.setDstIp(IpAddress("255.255.255.255"));
    package.setType(0x08);
    package.setCode(0x00);

    set_ethernet(package, options);
    set_ip(package, options);
    set_icmp(package, options);

    return package;
}

TCPPackage make_tcp(std::map<Keys, Option> options) {
    PCAP::TCPPackage package(package_buffer, snap_len, true);
    package.setSrcMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setDstMac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.setEtherType(0x0800);
    package.setVHL(0x45);
    package.setTOS(0x0);
    package.setTotalLength(0x003c);
    package.setID(0x1000);
    package.setFlags(0x0);
    package.setFragmentOffset(0x0);
    package.setTTL(0x64);
    package.setProtocol(0x06);
    package.setSrcIp(IpAddress("255.255.255.255"));
    package.setDstIp(IpAddress("255.255.255.255"));
    package.setSrcPort(1);
    package.setDstPort(1);
    package.setSeqNr(0x3323);
    package.setAckNr(0);
    package.setDataOffset(0x50);
    package.setFlags(0x02);
    package.setWindowSize(0x7210);
    package.setUrgentPtr(0x0000);
    
    set_ethernet(package, options);
    set_ip(package, options);
    set_tcp(package, options);

    return package;
}

}
}
