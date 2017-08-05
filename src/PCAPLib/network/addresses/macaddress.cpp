#include "macaddress.h"

#include <cstring>
#include <iomanip>
#include <sstream>

#include "../../helpers/helper.h"

namespace PCAP {

MacAddress::MacAddress(const std::string& mac) {
    PCAP::PCAPHelper::split_string<unsigned char, ETHER_ADDR_LEN>(mac, ':', m_mac, 16);
}

MacAddress::MacAddress(unsigned char *data) {
    memcpy(m_mac.data(), data, ETHER_ADDR_LEN);
}

MacAddress::MacAddress() {
    memset(m_mac.data(), 0xFF, ETHER_ADDR_LEN);
}

bool operator==(const MacAddress& lhs, const MacAddress& rhs) {
    return lhs.m_mac == rhs.m_mac;
}

std::ostream& operator<<(std::ostream& stream, const MacAddress& rhs) {
    stream << rhs.to_string();
    return stream;
}

std::string MacAddress::to_string() const {
    std::stringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        stream << std::hex << std::uppercase << int(m_mac[i]);
        if (i != ETHER_ADDR_LEN - 1)
            stream << ":";
    }
    return stream.str();
}

const unsigned char* MacAddress::data() const {
    return m_mac.data();
}

}