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
    ARPPackage(const unsigned char *p, unsigned int l, bool modify = false);
    IpAddress get_src_ip() const;
    IpAddress get_dst_ip() const;
    MacAddress get_src_arp_mac() const;
    MacAddress get_dst_arp_mac() const;
    unsigned short get_hardware_type() const;
    unsigned short get_protocol() const;
    unsigned char get_hardware_length() const;
    unsigned char get_protocol_length() const;
    unsigned short get_opcode() const;

    void set_src_ip(IpAddress ip);
    void set_dst_ip(IpAddress ip);
    void set_src_arp_mac(MacAddress mac);
    void set_dst_arp_mac(MacAddress mac);
    void set_hardware_type(unsigned short type);
    void set_protocol(unsigned short proto);
    void set_hardware_length(unsigned char l);
    void set_protocol_length(unsigned char l);
    void set_opcode(unsigned short code);

    unsigned int get_length() const override;

    friend bool operator==(const ARPPackage &lhs, const ARPPackage &rhs);
    friend bool operator!=(const ARPPackage &lhs, const ARPPackage &rhs);

  protected:
    sniffarp *m_arp;
};
}

#endif // ARPPACKAGE_H
