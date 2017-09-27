#ifndef IPPACKAGE_H
#define IPPACKAGE_H

#include <string>

#include "../addresses/ipaddress.h"
#include "../sniff/sniffip.h"
#include "ethernetpackage.h"

namespace PCAP {

class IPPackage : public EthernetPackage {
  public:
    IPPackage(const unsigned char *p, unsigned int l, bool modify = false);

    IpAddress get_src_ip() const;
    IpAddress get_dst_ip() const;
    unsigned char get_vhl() const;
    unsigned char get_tos() const;
    unsigned short get_total_length() const;
    unsigned short get_id() const;
    unsigned char get_ip_flags() const;
    unsigned short get_fragment_offset() const;
    unsigned char get_ttl() const;
    unsigned char get_protocol() const;

    void set_dst_ip(IpAddress ip);
    void set_src_ip(IpAddress ip);
    void set_vhl(unsigned char value);
    void set_tos(unsigned char value);
    void set_total_length(unsigned short length);
    void set_id(unsigned short id);
    void set_ip_flags(unsigned char flags);
    void set_fragment_offset(unsigned short fragment);
    void set_ttl(unsigned char ttl);
    void set_protocol(unsigned char protocol);

    friend bool operator==(const IPPackage &lhs, const IPPackage &rhs);
    friend bool operator!=(const IPPackage &lhs, const IPPackage &rhs);

  protected:
    sniffip *m_ip;
};
}

#endif
