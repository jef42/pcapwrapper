#ifndef PCAPHELPER_H
#define PCAPHELPER_H

#include <array>
#include <stdexcept>
#include <vector>

#include "../network/sniff/sniffip.h"
#include "../network/sniff/snifftcp.h"
#include "../network/sniff/sniffudp.h"
#include "../network/sniff/snifficmp.h"
#include "../network/addresses/ipaddress.h"
#include "../network/addresses/macaddress.h"

namespace PCAP {
namespace PCAPHelper {

void setIPChecksum(sniffip* ip);
void setICMPChecksum(sniffip *ip, snifficmp* icmp);
void setTCPChecksum(sniffip* ip, snifftcp* tcp, unsigned char* data);
void setUDPChecksum(sniffip *ip, sniffudp* udp, unsigned char* data);

PCAP::IpAddress getIp(const std::string& interface);
PCAP::MacAddress getMac(const std::string& interface);
PCAP::IpAddress getMask(const std::string& interface);
PCAP::IpAddress getRouterIp(const std::string& inteface);
PCAP::IpAddress getBroadcastIp(const std::string& inteface);
std::vector<PCAP::IpAddress> getIps(const PCAP::IpAddress& local_ip, const PCAP::IpAddress& network_mask);
PCAP::MacAddress getMac(const PCAP::IpAddress& target_ip, const std::string& interface);

template <typename T, int N>
bool split_string(const std::string& s, const char splitter, std::array<T,N>& array, int base = 10) {
    unsigned int i = 0;
    std::string tmp = s + splitter;
    size_t p = std::string::npos;
    while ((p = tmp.find(splitter, 0)) != std::string::npos) {
        try {
            std::string aux = tmp.substr(0, p);
            int b = std::stoi(aux, 0, base);
            if (i >= N) return false;
            array[i++] = b;
            tmp = tmp.substr(p+1, std::string::npos);
        } catch( std::invalid_argument& ex) {
            return false;
        }
    }
    if (i != N)
        return false;
    return true;
}

template <typename T>
unsigned short checksum(T* p, int count) {
    unsigned int sum = 0;
    unsigned short* addr = (unsigned short*)p;

    while( count > 1 )  {
        sum += *addr++;
        count -= 2;
    }

    if( count > 0 )
        sum += * (unsigned char *) addr;

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

}
}

#endif // PCAPHELPER_H
