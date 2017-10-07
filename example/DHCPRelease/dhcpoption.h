#ifndef DHCPOPTION_H
#define DHCPOPTION_H

#include <array>
#include <pcapwrapper/helpers/common.h>

template <int S> class DHCPOption {
  public:
    DHCPOption(PCAP::uchar code, std::initializer_list<PCAP::uchar> list) {
        m_result[0] = code;
        m_result[1] = (PCAP::uchar)list.size();
        int i = 2;
        for (auto &e : list) {
            m_result[i++] = e;
        }
    }

    std::array<PCAP::uchar, S + 2> get_array() { return m_result; }

  private:
    std::array<PCAP::uchar, S + 2> m_result;
};

#endif // DHCPOPTION_H
