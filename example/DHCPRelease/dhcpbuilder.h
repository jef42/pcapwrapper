#ifndef DHCPBUILDER_H
#define DHCPBUILDER_H

#include <array>
#include <netinet/in.h>
#include <stdio.h>

#include <pcapwrapper/helpers/constants.h>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>

#include "dhcpframe.h"

class DHCPBuilder {
  public:
    DHCPBuilder();

    void operator<<(PCAP::sniffethernet ethernet);
    void operator<<(PCAP::sniffip ip);
    void operator<<(PCAP::sniffudp udp);
    void operator<<(sniffdhcp dhcp);

    template <long unsigned int S>
    friend void operator<<(DHCPBuilder &dhcpbuilder,
                           std::array<unsigned char, S> data) {
        memcpy(&dhcpbuilder.m_package[dhcpbuilder.m_index], data.data(), S);
        dhcpbuilder.m_index += S;

        dhcpbuilder.m_ip->m_ip_len =
            htons(ntohs(dhcpbuilder.m_ip->m_ip_len) + S);
        dhcpbuilder.m_udp->m_length =
            htons(ntohs(dhcpbuilder.m_udp->m_length) + S);
    }

    void build();
    unsigned char *get_package() const;
    unsigned int get_length() const;

  private:
    unsigned char m_package[snap_len];
    unsigned int m_index;
    PCAP::sniffethernet *m_ethernet;
    PCAP::sniffip *m_ip;
    PCAP::sniffudp *m_udp;
    sniffdhcp *m_dhcp;
};

#endif // DHCPBUILDER_H
