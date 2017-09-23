#ifndef DHCPOPTION_H
#define DHCPOPTION_H

#include <array>

template <int S> class DHCPOption {
  public:
    DHCPOption(unsigned char code, std::initializer_list<unsigned char> list) {
        m_result[0] = code;
        m_result[1] = (unsigned char)list.size();
        int i = 2;
        for (auto &e : list) {
            m_result[i++] = e;
        }
    }

    std::array<unsigned char, S + 2> get_array() { return m_result; }

  private:
    std::array<unsigned char, S + 2> m_result;
};

#endif // DHCPOPTION_H
