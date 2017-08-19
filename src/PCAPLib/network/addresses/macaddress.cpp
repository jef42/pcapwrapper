#include "macaddress.h"

#include <cstring>
#include <iomanip>
#include <sstream>

#include "../../helpers/helper.h"

namespace PCAP {

MacAddress::MacAddress(const std::string& mac) {
    PCAP::PCAPHelper::split_string<unsigned char, ethernet_addr_len>(mac, ':', m_mac, 16);
}

MacAddress::MacAddress(unsigned char *data) {
    memcpy(m_mac.data(), data, ethernet_addr_len);
}

MacAddress::MacAddress() {
    memset(m_mac.data(), 0xFF, ethernet_addr_len);
}

bool operator==(const MacAddress& lhs, const MacAddress& rhs) noexcept{
    return lhs.m_mac == rhs.m_mac;
}

bool operator!=(const MacAddress& lhs, const MacAddress& rhs) noexcept{
    return !(lhs.m_mac == rhs.m_mac);
}

std::ostream& operator<<(std::ostream& stream, const MacAddress& rhs) {
    stream << rhs.to_string();
    return stream;
}

std::string MacAddress::to_string() const {
    std::stringstream stream;
    for (size_t i = 0; i < ethernet_addr_len; ++i) {
        stream << std::hex << std::uppercase << int(m_mac[i]);
        if (i != ethernet_addr_len - 1)
            stream << ":";
    }
    return stream.str();
}

const unsigned char* MacAddress::data() const noexcept {
    return m_mac.data();
}

}