#ifndef PCAPIPADDRESS_H
#define PCAPIPADDRESS_H

#include <string>
#include <array>
#include <ostream>

#include "../../helpers/constants.h"

namespace PCAP {

class IpAddress {
public:
    explicit IpAddress(const std::string& ip);
    explicit IpAddress(unsigned char *data);
    explicit IpAddress(unsigned long ip);
    explicit IpAddress();

    friend bool operator==(const IpAddress& lhs, const IpAddress& rhs);
    friend bool operator!=(const IpAddress& lhs, const IpAddress& rhs);
    friend bool operator<(const IpAddress& lhs, const IpAddress& rhs);
    friend std::ostream& operator<<(std::ostream& stream, const IpAddress& rhs);
    friend IpAddress operator&(const IpAddress& lhs, const IpAddress& rhs);

    std::string to_string() const;
    unsigned long to_long() const;
    const unsigned char* data() const;
private:
    std::array<unsigned char, IP_ADDR_LEN> m_ip;
};

}

#endif