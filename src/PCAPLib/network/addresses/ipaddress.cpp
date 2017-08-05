#include "ipaddress.h"

#include <cstring>

#include "../../helpers/helper.h"

namespace PCAP {

IpAddress::IpAddress(const std::string& ip) {
    PCAP::PCAPHelper::split_string<unsigned char, IP_ADDR_LEN>(ip, '.', m_ip, 10);
}

IpAddress::IpAddress(unsigned char *data) {
    memcpy(m_ip.data(), data, IP_ADDR_LEN);
}

IpAddress::IpAddress(unsigned long ip) {
    m_ip[0] = ip >> 24 & 0xFF;
    m_ip[1] = ip >> 16 & 0xFF;
    m_ip[2] = ip >> 8 & 0xFF;
    m_ip[3] = ip & 0xFF;
}

IpAddress::IpAddress() {
    memset(m_ip.data(), 0xFF, IP_ADDR_LEN);
}

bool operator==(const IpAddress& lhs, const IpAddress& rhs) {
    return lhs.m_ip[3] == rhs.m_ip[3] &&
           lhs.m_ip[2] == rhs.m_ip[2] &&
           lhs.m_ip[1] == rhs.m_ip[1] &&
           lhs.m_ip[0] == rhs.m_ip[0];
}

bool operator!=(const IpAddress& lhs, const IpAddress& rhs) {
    return !(lhs == rhs);
}

bool operator<(const IpAddress& lhs, const IpAddress& rhs) {
    return lhs.m_ip < rhs.m_ip;
}

std::ostream& operator<<(std::ostream& stream, const IpAddress& rhs) {
    stream << rhs.to_string();
    return stream;
}

IpAddress operator&(const IpAddress& lhs, const IpAddress& rhs) {
    return IpAddress(lhs.to_long() & rhs.to_long());
}

std::string IpAddress::to_string() const {
    std::string result = "";
    for (int i = 0; i < IP_ADDR_LEN; ++i) {
        result.append(std::to_string(int(m_ip[i])));
        if (i != IP_ADDR_LEN - 1)
            result.append(".");
    }
    return result;
}

unsigned long IpAddress::to_long() const {
    return 0 | m_ip[0] << 24 | m_ip[1] << 16 | m_ip[2] << 8 | m_ip[3];
}

const unsigned char* IpAddress::data() const {
    return m_ip.data();
}

}