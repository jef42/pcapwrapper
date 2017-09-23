#ifndef BUILDER_H
#define BUILDER_H

#include <map>
#include <memory>

#include "../addresses/ipaddress.h"
#include "../addresses/macaddress.h"
#include "../packages/arppackage.h"
#include "../packages/icmppackage.h"
#include "../packages/tcppackage.h"
#include "../packages/udppackage.h"
#include "keys.h"

namespace PCAP {
namespace PCAPBuilder {

class Option {
  public:
    explicit Option(unsigned int value) : m_value_int{value} {}

    explicit Option(unsigned short value) : m_value_short{value} {}

    explicit Option(unsigned char value) : m_value_char{value} {}

    explicit Option(PCAP::IpAddress ip) : m_value_ip{ip} {}

    explicit Option(PCAP::MacAddress mac) : m_value_mac{mac} {}

    Option(const Option &rhs) noexcept = default;
    Option &operator=(const Option &rhs) noexcept = default;
    Option(Option &&rhs) noexcept = default;
    Option &operator=(Option &&rhs) noexcept = default;

    friend void set_ethernet(auto &package, std::map<Keys, Option> &options);
    friend void set_ip(auto &package, std::map<Keys, Option> &options);
    friend void set_udp(auto &package, std::map<Keys, Option> &options);
    friend void set_icmp(auto &package, std::map<Keys, Option> &options);
    friend void set_tcp(auto &package, std::map<Keys, Option> &options);
    friend void set_arp(auto &package, std::map<Keys, Option> &options);

  private:
    union {
        unsigned int m_value_int;
        unsigned short m_value_short;
        unsigned char m_value_char;
        PCAP::IpAddress m_value_ip;
        PCAP::MacAddress m_value_mac;
    };
};

ARPPackage make_arp(std::map<Keys, Option> options);
UDPPackage make_udp(std::map<Keys, Option> options);
ICMPPackage make_icmp(std::map<Keys, Option> options);
TCPPackage make_tcp(std::map<Keys, Option> options);
}
}

#endif // BUILDER_H
