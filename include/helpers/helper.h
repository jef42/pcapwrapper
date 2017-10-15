#ifndef PCAPHELPER_H
#define PCAPHELPER_H

#include <array>
#include <stdexcept>
#include <vector>
#include "../network/addresses/ipaddress.h"
#include "../network/addresses/macaddress.h"
#include "../network/sniff/snifficmp.h"
#include "../network/sniff/sniffip.h"
#include "../network/sniff/snifftcp.h"
#include "../network/sniff/sniffudp.h"

namespace PCAP {
namespace PCAPHelper {

void set_ip_checksum(sniffip *ip);
void set_icmp_checksum(sniffip *ip, snifficmp *icmp);
void set_tcp_checksum(sniffip *ip, snifftcp *tcp, uchar *data);
void set_udp_checksum(sniffip *ip, sniffudp *udp, uchar *data);

bool setIp(PCAP::uchar *ip, const std::string &ip_value, int base);
bool setMac(PCAP::uchar *addr, const std::string &ethernet_value, int base);

PCAP::IpAddress get_ip(const std::string &interface);
PCAP::MacAddress get_mac(const std::string &interface);
PCAP::IpAddress get_mask(const std::string &interface);
PCAP::IpAddress get_router_ip(const std::string &inteface);
PCAP::IpAddress get_broadcast_ip(const std::string &inteface);
std::vector<PCAP::IpAddress> get_ips(const PCAP::IpAddress &local_ip,
                                    const PCAP::IpAddress &network_mask);
PCAP::MacAddress get_mac(const PCAP::IpAddress &target_ip,
                        const std::string &interface);

template <typename T, int N>
bool split_string(const std::string &s, const char splitter,
                  std::array<T, N> &array, int base = 10) {
    uint i = 0;
    std::string tmp = s + splitter;
    size_t p = std::string::npos;
    while ((p = tmp.find(splitter, 0)) != std::string::npos) {
        try {
            std::string aux = tmp.substr(0, p);
            int b = std::stoi(aux, 0, base);
            if (i >= N)
                return false;
            array[i++] = b;
            tmp = tmp.substr(p + 1, std::string::npos);
        } catch (std::invalid_argument &ex) {
            return false;
        }
    }
    if (i != N)
        return false;
    return true;
}

template <typename T> ushort checksum(T *p, int count) {
    uint sum = 0;
    ushort *addr = (ushort *)p;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uchar *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}
}
}

#endif // PCAPHELPER_H
