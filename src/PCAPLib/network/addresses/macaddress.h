#ifndef PCAPMACADDRESS_H
#define PCAPMACADDRESS_H

#include <string>
#include <array>
#include <ostream>

#include "../../helpers/constants.h"

namespace PCAP {

class MacAddress {
public:
    explicit MacAddress(const std::string& mac);
    explicit MacAddress(unsigned char *data);
    explicit MacAddress();

    friend bool operator==(const MacAddress& lhs, const MacAddress& rhs);
    friend std::ostream& operator<<(std::ostream& stream, const MacAddress& rhs);

    std::string to_string() const;
    const unsigned char* data() const;
private:
    std::array<unsigned char, ETHER_ADDR_LEN> m_mac;
};

}

#endif