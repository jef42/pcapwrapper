#ifndef PCAPMACADDRESS_H
#define PCAPMACADDRESS_H

#include "../../helpers/common.h"
#include "../../helpers/constants.h"
#include <array>
#include <ostream>
#include <string>

namespace PCAP {

class MacAddress {
  public:
    explicit MacAddress(const std::string &mac);
    explicit MacAddress(uchar *data);
    explicit MacAddress();

    friend bool operator==(const MacAddress &lhs,
                           const MacAddress &rhs) noexcept;
    friend bool operator!=(const MacAddress &lhs,
                           const MacAddress &rhs) noexcept;
    friend std::ostream &operator<<(std::ostream &stream,
                                    const MacAddress &rhs);

    std::string to_string() const;
    const uchar *data() const noexcept;

  private:
    std::array<uchar, ethernet_addr_len> m_mac;
};
}

#endif