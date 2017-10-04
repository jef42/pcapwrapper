#ifndef SESSION_H
#define SESSION_H

#include "../addresses/ipaddress.h"
#include <string>
#include <tuple>

namespace PCAP {

class Session {
  public:
    Session(IpAddress ip_host, IpAddress ip_dest,
            const ushort port_host, const ushort port_dest);

    friend bool operator==(const Session &lhs, const Session &rhs) noexcept;
    friend bool operator!=(const Session &lhs, const Session &rhs) noexcept;

    std::tuple<IpAddress, IpAddress> get_ips() const;
    std::tuple<ushort, ushort> get_ports() const;

  private:
    IpAddress m_ip_host;
    IpAddress m_ip_dest;
    ushort m_port_host;
    ushort m_port_dest;
};
}

#endif
