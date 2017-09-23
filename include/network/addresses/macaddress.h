#ifndef PCAPMACADDRESS_H
#define PCAPMACADDRESS_H

#include <array>
#include <ostream>
#include <string>

#include "../../helpers/constants.h"

namespace PCAP {

class MacAddress {
  public:
    explicit MacAddress(const std::string &mac);
    explicit MacAddress(unsigned char *data);
    explicit MacAddress();

    friend bool operator==(const MacAddress &lhs,
                           const MacAddress &rhs) noexcept;
    friend bool operator!=(const MacAddress &lhs,
                           const MacAddress &rhs) noexcept;
    friend std::ostream &operator<<(std::ostream &stream,
                                    const MacAddress &rhs);

    std::string to_string() const;
    const unsigned char *data() const noexcept;

  private:
    std::array<unsigned char, ethernet_addr_len> m_mac;
};
}

#endif