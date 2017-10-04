#ifndef PCAPIPADDRESS_H
#define PCAPIPADDRESS_H

#include <array>
#include <ostream>
#include <string>

#include "../../helpers/constants.h"

namespace PCAP {

class IpAddress {
  public:
    explicit IpAddress(const std::string &ip);
    explicit IpAddress(uchar *data);
    explicit IpAddress(ulong ip);
    explicit IpAddress();

    IpAddress(const IpAddress &rhs) noexcept = default;
    IpAddress(IpAddress &&rhs) noexcept = default;
    IpAddress &operator=(const IpAddress &) noexcept = default;
    IpAddress &operator=(IpAddress &&) noexcept = default;

    friend bool operator==(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator!=(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator<(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator>(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend std::ostream &operator<<(std::ostream &stream, const IpAddress &rhs);
    friend IpAddress operator&(const IpAddress &lhs,
                               const IpAddress &rhs) noexcept;

    std::string to_string() const;
    ulong to_long() const noexcept;
    const uchar *data() const noexcept;

  private:
    std::array<uchar, ip_addr_len> m_ip;
};
}

#endif