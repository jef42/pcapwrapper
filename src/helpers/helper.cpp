#include "../../include/helpers/helper.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <net/if.h>
#include <netinet/in.h>
#include <numeric>
#include <pcap/pcap.h>
#include <sstream>
#include <string.h>
#include <sys/ioctl.h>
#include <thread>
#include <vector>

#include "../../include/controller.hpp"
#include "../../include/helpers/constants.h"
#include "../../include/helpers/listeners/maclistener.h"
#include "../../include/interfaces/interface.h"
#include "../../include/network/addresses/ipaddress.h"
#include "../../include/network/addresses/macaddress.h"
#include "../../include/network/packages/arppackage.h"
#include "../../include/processors/processor.h"

namespace PCAP {
namespace PCAPHelper {

namespace {
struct pseudo_header {
    uchar s_addr[4];
    uchar d_addr[4];
    uchar reserved = 0x00;
    uchar protocol;
    ushort length;
};
}

void set_ip_checksum(sniffip *ip) {
    ip->m_ip_sum = 0x0000;
    ip->m_ip_sum = checksum<sniffip>(ip, sizeof(*ip));
}

void set_icmp_checksum(sniffip *ip, snifficmp *icmp) {
    icmp->m_checksum = 0x0000;
    icmp->m_checksum =
        checksum((char *)icmp, ntohs(ip->m_ip_len) - (IP_HL(ip) * 4));
}

void set_tcp_checksum(sniffip *ip, snifftcp *tcp, uchar *data) {
    tcp->m_th_sum = 0x0000;

    pseudo_header pseudo_h;
    memcpy(&pseudo_h.s_addr, &ip->m_ip_src, ip_addr_len);
    memcpy(&pseudo_h.d_addr, &ip->m_ip_dst, ip_addr_len);
    pseudo_h.reserved = 0x00;
    pseudo_h.protocol = ip->m_ip_p;
    pseudo_h.length = htons(ntohs(ip->m_ip_len) - (IP_HL(ip) * 4));

    char packet[1500];
    memset(packet, '\0', 1500);
    memcpy(packet, &pseudo_h, sizeof(pseudo_h));
    memcpy(&packet[sizeof(pseudo_h)], tcp, sizeof(*tcp));
    memcpy(&packet[sizeof(pseudo_h) + sizeof(*tcp)], data,
           ntohs(ip->m_ip_len) - (IP_HL(ip) * 4 - sizeof(*tcp)));

    tcp->m_th_sum = checksum(&packet, ntohs(ip->m_ip_len) - (IP_HL(ip) * 4) +
                                          sizeof(pseudo_h));
}

void set_udp_checksum(sniffip *ip, sniffudp *udp, uchar *data) {
    udp->m_checksum = 0x0000;

    pseudo_header pseudo_h;
    memset(&pseudo_h, '\0', sizeof(pseudo_h));
    memcpy(&pseudo_h.s_addr, &ip->m_ip_src, ip_addr_len);
    memcpy(&pseudo_h.d_addr, &ip->m_ip_dst, ip_addr_len);
    pseudo_h.protocol = ip->m_ip_p;
    pseudo_h.reserved = 0x00;
    pseudo_h.length = htons(ntohs(ip->m_ip_len) - (IP_HL(ip) * 4));

    char packet[1500];
    memset(packet, '\0', 1500);
    memcpy(packet, &pseudo_h, sizeof(pseudo_h));
    memcpy(&packet[sizeof(pseudo_h)], udp, sizeof(*udp));
    memcpy(&packet[sizeof(pseudo_h) + sizeof(*udp)], data,
           ntohs(udp->m_length) - sizeof(*udp));

    udp->m_checksum =
        checksum(&packet, ntohs(udp->m_length) + sizeof(pseudo_h));
}

bool setIp(PCAP::uchar *ip, const std::string &ip_value, int base) {
    std::array<PCAP::uchar, ip_addr_len> array;
    bool successful = PCAP::PCAPHelper::split_string<PCAP::uchar, ip_addr_len>(
        ip_value, '.', array, base);
    if (successful) {
        memcpy(ip, array.data(), ip_addr_len);
    }
    return successful;
}

bool setMac(PCAP::uchar *addr, const std::string &ethernet_value, int base) {
    std::array<PCAP::uchar, ethernet_addr_len> array;
    bool sucessful =
        PCAP::PCAPHelper::split_string<PCAP::uchar, ethernet_addr_len>(
            ethernet_value, ':', array, base);
    if (sucessful) {
        memcpy(addr, array.data(), ethernet_addr_len);
    }
    return sucessful;
}

pcap_if_t *get_all_devs() {
    pcap_if_t *alldevs;
    static char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        return nullptr;
    }
    return alldevs;
}

PCAP::IpAddress get_ip(const std::string &interface) {
    pcap_if_t *all_devs = get_all_devs();
    for (pcap_if_t *dev = all_devs; dev != NULL; dev = dev->next) {
        if (dev->name == interface) {
            for (pcap_addr_t *a = dev->addresses; a != NULL; a = a->next) {
                if (a->addr->sa_family == AF_INET) {
                    std::string result =
                        inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
                    pcap_freealldevs(all_devs);
                    return PCAP::IpAddress(result);
                }
            }
        }
    }
    pcap_freealldevs(all_devs);
    return PCAP::IpAddress();
}

PCAP::IpAddress get_mask(const std::string &interface) {
    pcap_if_t *all_devs = get_all_devs();
    for (pcap_if_t *dev = all_devs; dev != NULL; dev = dev->next) {
        if (dev->name == interface) {
            for (pcap_addr_t *a = dev->addresses; a != NULL; a = a->next) {
                if (a->netmask && a->netmask->sa_family == AF_INET) {
                    std::string result =
                        inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr);
                    pcap_freealldevs(all_devs);
                    return PCAP::IpAddress(result);
                }
            }
        }
    }
    pcap_freealldevs(all_devs);
    return PCAP::IpAddress();
}

PCAP::MacAddress get_mac(const std::string &interface) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        std::stringstream stream;
        for (int i = 0; i < 6; ++i) {
            stream << std::setfill('0') << std::setw(2) << std::hex
                   << std::uppercase << stoi(std::to_string(static_cast<uchar>(
                                            s.ifr_addr.sa_data[i])));
            if (i != 5)
                stream << ":";
        }
        return PCAP::MacAddress(stream.str());
    }
    return PCAP::MacAddress();
}

std::vector<PCAP::IpAddress> get_ips(const PCAP::IpAddress &local_ip,
                                     const PCAP::IpAddress &net_mask) {
    std::vector<PCAP::IpAddress> result;
    ulong ip = local_ip.to_long();
    ulong mask = net_mask.to_long();
    ulong tmp = ip & mask;
    while ((tmp & mask) == (ip & mask)) {
        result.emplace_back(PCAP::IpAddress(tmp++));
    }
    return result;
}

PCAP::IpAddress get_router_ip(const std::string &interface) {
    ulong ip = get_ip(interface).to_long();
    ulong mask = get_mask(interface).to_long();
    ulong tmp = ip & mask;
    return PCAP::IpAddress(tmp + 1);
}

PCAP::IpAddress get_broadcast_ip(const std::string &interface) {
    ulong ip = get_ip(interface).to_long();
    ulong mask = get_mask(interface).to_long();
    ulong tmp = ip | ~mask;
    return PCAP::IpAddress(tmp);
}

PCAP::MacAddress get_mac(const PCAP::IpAddress &target_ip,
                         const std::string &interface) {
    PCAP::IpAddress local_ip = get_ip(interface);
    PCAP::MacAddress local_mac = get_mac(interface);
    auto mac_listener = std::make_shared<MacListener>(target_ip);
    auto controller =
        std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(
            interface);
    controller->add_listener(mac_listener);
    controller->start();

    bool run_flag = true;
    auto f = std::async(std::launch::async, [&run_flag, &controller, local_ip,
                                             target_ip, local_mac]() {
        uchar package_buffer[snap_len];
        memset(package_buffer, '\0', snap_len);

        while (run_flag) {
            PCAP::ARPPackage package(package_buffer, (uint)snap_len, true);
            package.set_src_mac(local_mac);
            package.set_dst_mac(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"));
            package.set_ether_type(0x0806);
            package.set_hardware_type(0x01);
            package.set_protocol(0x0800);
            package.set_hardware_length(0x06);
            package.set_protocol_length(0x04);
            package.set_opcode(0x01);
            package.set_src_arp_mac(local_mac);
            package.set_src_ip(local_ip);
            package.set_dst_arp_mac(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"));
            package.set_dst_ip(target_ip);
            controller->write(package.get_package(), package.get_length());

            using namespace std::chrono_literals;
            std::this_thread::sleep_for(1s);
        }
    });

    auto mac_result = mac_listener->get_mac();
    run_flag = false;
    f.get();

    controller->remove_listener(mac_listener);
    controller->stop();

    return mac_result;
}
}
}
