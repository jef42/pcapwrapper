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

    friend bool operator== (const Session& lhs, const Session& rhs) noexcept;
    friend bool operator!= (const Session& lhs, const Session& rhs) noexcept;

    std::tuple<IpAddress, IpAddress> get_ips() const;
    std::tuple<unsigned short, unsigned short> get_ports() const;
private:
    IpAddress m_ip_host;
    IpAddress m_ip_dest;
    unsigned short m_port_host;
    unsigned short m_port_dest;
};

}

#endif
