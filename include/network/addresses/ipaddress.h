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

    IpAddress(const IpAddress& rhs) noexcept = default;
    IpAddress(IpAddress&& rhs) noexcept = default;
    IpAddress& operator=(const IpAddress&) noexcept = default;
    IpAddress& operator=(IpAddress&&) noexcept = default;

    friend bool operator==(const IpAddress& lhs, const IpAddress& rhs) noexcept;
    friend bool operator!=(const IpAddress& lhs, const IpAddress& rhs) noexcept;
    friend bool operator<(const IpAddress& lhs, const IpAddress& rhs) noexcept;
    friend std::ostream& operator<<(std::ostream& stream, const IpAddress& rhs);
    friend IpAddress operator&(const IpAddress& lhs, const IpAddress& rhs) noexcept;

    std::string to_string() const;
    unsigned long to_long() const noexcept;
    const unsigned char* data() const noexcept;
private:
    std::array<unsigned char, ip_addr_len> m_ip;
};

}

#endif