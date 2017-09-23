#ifndef IP_PORT_H
#define IP_PORT_H

#include <ctime>
#include <iomanip>
#include <ostream>
#include <string>

#include <pcapwrapper/network/addresses/ipaddress.h>

struct IPPort {
    IPPort(const PCAP::IpAddress ip, unsigned short src_port,
           unsigned short dst_port)
        : m_ip(ip), m_src_port(src_port), m_dst_port(dst_port) {
        m_time = std::time(nullptr);
    }

    bool operator==(const IPPort &rhs) noexcept {
        return m_ip == rhs.m_ip && m_src_port == rhs.m_src_port &&
               m_dst_port == rhs.m_dst_port;
    }

    friend std::ostream &operator<<(std::ostream &output, const IPPort &rhs);

    std::time_t m_time;
    PCAP::IpAddress m_ip;
    unsigned short m_src_port;
    unsigned short m_dst_port;
};

#endif
