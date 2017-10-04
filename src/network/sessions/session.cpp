#include "../../../include/network/sessions/session.h"

#include <utility>

namespace PCAP {

Session::Session(IpAddress ip_host, IpAddress ip_dest,
                 const ushort port_host, const ushort port_dest)
    : m_ip_host{ip_host}, m_ip_dest{ip_dest}, m_port_host{port_host},
      m_port_dest{port_dest} {}

std::tuple<IpAddress, IpAddress> Session::get_ips() const {
    return std::make_tuple(m_ip_host, m_ip_dest);
}

std::tuple<ushort, ushort> Session::get_ports() const {
    return std::make_tuple(m_port_host, m_port_dest);
}

bool operator==(const Session &lhs, const Session &rhs) noexcept {
    return (lhs.m_ip_host == rhs.m_ip_host || lhs.m_ip_host == rhs.m_ip_dest) &&
           (rhs.m_ip_host == lhs.m_ip_host || rhs.m_ip_host == lhs.m_ip_dest) &&
           (lhs.m_port_host == rhs.m_port_host ||
            lhs.m_port_host == rhs.m_port_dest) &&
           (rhs.m_port_host == lhs.m_port_host ||
            rhs.m_port_host == lhs.m_port_dest);
}

bool operator!=(const Session &lhs, const Session &rhs) noexcept {
    return !(lhs == rhs);
}
}
