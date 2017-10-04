#ifndef IPPACKAGE_H
#define IPPACKAGE_H

#include <string>

#include "../addresses/ipaddress.h"
#include "../sniff/sniffip.h"
#include "ethernetpackage.h"

namespace PCAP {

class IPPackage : public EthernetPackage {
  public:
    IPPackage(const uchar *p, uint l, bool modify = false);

    IpAddress get_src_ip() const;
    IpAddress get_dst_ip() const;
    uchar get_vhl() const;
    uchar get_tos() const;
    ushort get_total_length() const;
    ushort get_id() const;
    uchar get_ip_flags() const;
    ushort get_fragment_offset() const;
    uchar get_ttl() const;
    uchar get_protocol() const;

    void set_dst_ip(IpAddress ip);
    void set_src_ip(IpAddress ip);
    void set_vhl(uchar value);
    void set_tos(uchar value);
    void set_total_length(ushort length);
    void set_id(ushort id);
    void set_ip_flags(uchar flags);
    void set_fragment_offset(ushort fragment);
    void set_ttl(uchar ttl);
    void set_protocol(uchar protocol);

    friend bool operator==(const IPPackage &lhs, const IPPackage &rhs);
    friend bool operator!=(const IPPackage &lhs, const IPPackage &rhs);

  protected:
    sniffip *m_ip;
};
}

#endif
