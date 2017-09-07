#include "../../../include/network/addresses/ipaddress.h"

#include <cstring>
#include <stdexcept>

#include "../../../include/helpers/helper.h"

namespace PCAP {

IpAddress::IpAddress(const std::string& ip) {
    if (!PCAP::PCAPHelper::split_string<unsigned char, ip_addr_len>(ip, '.', m_ip, 10))
        throw std::runtime_error("Wrong argument");
}

IpAddress::IpAddress(unsigned char *data) {
    memcpy(m_ip.data(), data, ip_addr_len);
}

IpAddress::IpAddress(unsigned long ip) {
    m_ip[0] = ip >> 24 & 0xFF;
    m_ip[1] = ip >> 16 & 0xFF;
    m_ip[2] = ip >> 8 & 0xFF;
    m_ip[3] = ip & 0xFF;
}

IpAddress::IpAddress() {
    memset(m_ip.data(), 0xFF, ip_addr_len);
}

bool operator==(const IpAddress& lhs, const IpAddress& rhs) noexcept {
    return lhs.m_ip[3] == rhs.m_ip[3] &&
           lhs.m_ip[2] == rhs.m_ip[2] &&
           lhs.m_ip[1] == rhs.m_ip[1] &&
           lhs.m_ip[0] == rhs.m_ip[0];
}

bool operator!=(const IpAddress& lhs, const IpAddress& rhs) noexcept {
    return !(lhs == rhs);
}

bool operator<(const IpAddress& lhs, const IpAddress& rhs) noexcept {
    return lhs.m_ip < rhs.m_ip;
}

bool operator>(const IpAddress& lhs, const IpAddress& rhs) noexcept {
    return lhs.m_ip > rhs.m_ip;
}

std::ostream& operator<<(std::ostream& stream, const IpAddress& rhs) {
    stream << rhs.to_string();
    return stream;
}

IpAddress operator&(const IpAddress& lhs, const IpAddress& rhs) noexcept {
    return IpAddress(lhs.to_long() & rhs.to_long());
}

std::string IpAddress::to_string() const {
    std::string result = "";
    for (size_t i = 0; i < ip_addr_len; ++i) {
        result.append(std::to_string(int(m_ip[i])));
        if (i != ip_addr_len - 1)
            result.append(".");
    }
    return result;
}

unsigned long IpAddress::to_long() const noexcept {
    return 0 | m_ip[0] << 24 | m_ip[1] << 16 | m_ip[2] << 8 | m_ip[3];
}

const unsigned char* IpAddress::data() const noexcept {
    return m_ip.data();
}

}