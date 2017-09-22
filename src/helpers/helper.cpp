#include "../../include/helpers/helper.h"

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstring>
#include <string.h>
#include <algorithm>
#include <vector>
#include <numeric>
#include <iomanip>
#include <sstream>
#include <pcap/pcap.h>
#include <thread>

#include "../../include/helpers/constants.h"
#include "../../include/controller.hpp"
#include "../../include/interfaces/interface.h"
#include "../../include/processors/processor.h"
#include "../../include/network/packages/arppackage.h"
#include "../../include/network/addresses/macaddress.h"
#include "../../include/network/addresses/ipaddress.h"
#include "../../include/helpers/listeners/maclistener.h"

namespace PCAP {
namespace PCAPHelper {

struct pseudo_header {
    unsigned char s_addr[4];
    unsigned char d_addr[4];
    unsigned char reserved = 0x00;
    unsigned char protocol;
    unsigned short length;
};

void setIPChecksum(sniffip* ip) {
    ip->m_ip_sum = 0x0000;
    ip->m_ip_sum = checksum<sniffip>(ip, sizeof(*ip));
}

void setICMPChecksum(sniffip *ip, snifficmp* icmp) {
    icmp->m_checksum = 0x0000;
    icmp->m_checksum = checksum((char*)icmp, ntohs(ip->m_ip_len) - (IP_HL(ip) * 4));
}

void setTCPChecksum(sniffip *ip, snifftcp *tcp, snifftcpopt *tcp_opt, unsigned char* data) {
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
    if (TH_OFF(tcp) > 5)
        memcpy(&packet[sizeof(pseudo_h) + sizeof(*tcp)], tcp_opt, sizeof(*tcp_opt));
    memcpy(&packet[sizeof(pseudo_h) + TH_OFF(tcp) * 4], data, IP_HL(ip)*4-(sizeof(*ip)-TH_OFF(tcp) * 4));

    tcp->m_th_sum = checksum(&packet, ntohs(ip->m_ip_len) - (IP_HL(ip) * 4) + sizeof(pseudo_h));
}

void setUDPChecksum(sniffip* ip, sniffudp *udp, unsigned char* data) {
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
    memcpy(&packet[sizeof(pseudo_h) + sizeof(*udp)], data, ntohs(udp->m_length)-sizeof(*udp));

    udp->m_checksum = checksum(&packet, ntohs(udp->m_length) + sizeof(pseudo_h));
}

pcap_if_t* get_all_devs() {
    pcap_if_t *alldevs;
    static char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) != 0) {
        return nullptr;
    }
    return alldevs;
}

PCAP::IpAddress getIp(const std::string& interface) {
    pcap_if_t* all_devs = get_all_devs();
    for(pcap_if_t *dev=all_devs; dev!=NULL; dev=dev->next) {
        if (dev->name == interface) {
            for(pcap_addr_t *a=dev->addresses; a!=NULL; a=a->next) {
                if(a->addr->sa_family == AF_INET) {
                    std::string result = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
                    pcap_freealldevs(all_devs);
                    return PCAP::IpAddress(result);
                }
            }
        }
    }
    pcap_freealldevs(all_devs);
    return PCAP::IpAddress();
}

PCAP::IpAddress getMask(const std::string& interface) {
    pcap_if_t* all_devs = get_all_devs();
    for(pcap_if_t *dev=all_devs; dev!=NULL; dev=dev->next) {
        if (dev->name == interface) {
            for(pcap_addr_t *a=dev->addresses; a!=NULL; a=a->next) {
                if(a->netmask && a->netmask->sa_family == AF_INET) {
                    std::string result = inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr);
                    pcap_freealldevs(all_devs);
                    return PCAP::IpAddress(result);
                }
            }
        }
    }
    pcap_freealldevs(all_devs);;
    return PCAP::IpAddress();
}

PCAP::MacAddress getMac(const std::string& interface) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        std::stringstream stream;
        for (int i = 0; i < 6; ++i) {
            stream << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << stoi(std::to_string(static_cast<unsigned char>(s.ifr_addr.sa_data[i])));
            if (i != 5)
                stream << ":";
        }
        return PCAP::MacAddress(stream.str());
    }
    return PCAP::MacAddress();
}

std::vector<PCAP::IpAddress> getIps(const PCAP::IpAddress& local_ip, const PCAP::IpAddress& net_mask) {
    std::vector<PCAP::IpAddress> result;
    unsigned long ip = local_ip.to_long();
    unsigned long mask = net_mask.to_long();
    unsigned long tmp = ip & mask;
    while ((tmp & mask) == (ip & mask)) {
        result.emplace_back(PCAP::IpAddress(tmp++));
    }
    return result;
}

PCAP::IpAddress getRouterIp(const std::string& interface) {
    unsigned long ip = getIp(interface).to_long();
    unsigned long mask = getMask(interface).to_long();
    unsigned long tmp = ip & mask;
    return PCAP::IpAddress(tmp + 1);
}

PCAP::IpAddress getBroadcastIp(const std::string& interface) {
    unsigned long ip = getIp(interface).to_long();
    unsigned long mask = getMask(interface).to_long();
    unsigned long tmp = ip | ~mask;
    return PCAP::IpAddress(tmp);
}

PCAP::MacAddress getMac(const PCAP::IpAddress& target_ip, const std::string& interface) {
    PCAP::IpAddress local_ip = getIp(interface);
    PCAP::MacAddress local_mac = getMac(interface);
    auto mac_listener = std::make_shared<MacListener>(target_ip);
    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::Processor>>(interface);
    controller->addListener(mac_listener);
    controller->start();

    bool run_flag = true;
    auto f = std::async(std::launch::async, [&run_flag, &controller, local_ip, target_ip, local_mac](){
        unsigned char package_buffer[snap_len];
        memset(package_buffer, '\0', snap_len);

        while (run_flag) {
            PCAP::ARPPackage package(package_buffer, (unsigned int)snap_len, true);
            package.setSrcMac(local_mac);
            package.setDstMac(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"));
            package.setEtherType(0x0806);
            package.setHardwareType(0x01);
            package.setProtocol(0x0800);
            package.setHardwareLength(0x06);
            package.setProtocolLength(0x04);
            package.setOpcode(0x01);
            package.setSrcArpMac(local_mac);
            package.setSrcIp(local_ip);
            package.setDstArpMac(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"));
            package.setDstIp(target_ip);
            controller->write(package.getPackage(), package.getLength());

            using namespace std::chrono_literals;
            std::this_thread::sleep_for(1s);
        }
    });

    auto mac_result = mac_listener->getMac();
    run_flag = false;
    f.get();

    controller->removeListener(mac_listener);
    controller->stop();

    return mac_result;

}

}
}
