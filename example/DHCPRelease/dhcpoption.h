#ifndef DHCPOPTION_H
#define DHCPOPTION_H

#include <array>

template <int S> class DHCPOption {
  public:
    DHCPOption(uchar code, std::initializer_list<uchar> list) {
        m_result[0] = code;
        m_result[1] = (uchar)list.size();
        int i = 2;
        for (auto &e : list) {
            m_result[i++] = e;
        }
    }

    std::array<uchar, S + 2> get_array() { return m_result; }

  private:
    std::array<uchar, S + 2> m_result;
};

#endif // DHCPOPTION_H
