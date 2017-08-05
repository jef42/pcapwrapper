#ifndef SESSION_H
#define SESSION_H

#include <string>
#include <tuple>
#include "../addresses/ipaddress.h"

namespace PCAP {

class Session {
public:
    Session(IpAddress ip_host, IpAddress ip_dest,
            const unsigned short port_host, const unsigned short port_dest);
    Session(const Session& rhs);
    Session(Session&& rhs) noexcept;
    Session& operator=(const Session& rhs) = default;
    Session& operator=(Session&& rhs) noexcept = default;

    friend bool operator == (const Session& lhs, const Session& rhs);

    auto get_ips() const;
    auto get_ports() const;
private:
    IpAddress m_ip_host;
    IpAddress m_ip_dest;
    unsigned short m_port_host;
    unsigned short m_port_dest;
};

}

#endif
