#ifndef ARPPACKAGE_H
#define ARPPACKAGE_H

#include <string>

#include "../addresses/ipaddress.h"
#include "../addresses/macaddress.h"
#include "../sniff/sniffarp.h"
#include "ethernetpackage.h"

namespace PCAP {

class ARPPackage : public EthernetPackage {
  public:
    ARPPackage(const uchar *p, uint l, bool modify = false);
    IpAddress get_src_ip() const;
    IpAddress get_dst_ip() const;
    MacAddress get_src_arp_mac() const;
    MacAddress get_dst_arp_mac() const;
    ushort get_hardware_type() const;
    ushort get_protocol() const;
    uchar get_hardware_length() const;
    uchar get_protocol_length() const;
    ushort get_opcode() const;

    void set_src_ip(IpAddress ip);
    void set_dst_ip(IpAddress ip);
    void set_src_arp_mac(MacAddress mac);
    void set_dst_arp_mac(MacAddress mac);
    void set_hardware_type(ushort type);
    void set_protocol(ushort proto);
    void set_hardware_length(uchar l);
    void set_protocol_length(uchar l);
    void set_opcode(ushort code);

    uint get_length() const override;

    friend bool operator==(const ARPPackage &lhs, const ARPPackage &rhs);
    friend bool operator!=(const ARPPackage &lhs, const ARPPackage &rhs);

  protected:
    sniffarp *m_arp;
};
}

#endif // ARPPACKAGE_H
