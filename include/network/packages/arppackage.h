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
    IpAddress getSrcIp() const;
    IpAddress getDstIp() const;
    MacAddress getSrcArpMac() const;
    MacAddress getDstArpMac() const;
    unsigned short getHardwareType() const;
    unsigned short getProtocol() const;
    unsigned char getHardwareLength() const;
    unsigned char getProtocolLength() const;
    unsigned short getOpcode() const;

    void setSrcIp(IpAddress ip);
    void setDstIp(IpAddress ip);
    void setSrcArpMac(MacAddress mac);
    void setDstArpMac(MacAddress mac);
    void setHardwareType(unsigned short type);
    void setProtocol(unsigned short proto);
    void setHardwareLength(unsigned char l);
    void setProtocolLength(unsigned char l);
    void setOpcode(unsigned short code);

    unsigned int getLength() const override;

    friend bool operator==(const ARPPackage &lhs, const ARPPackage &rhs);
    friend bool operator!=(const ARPPackage &lhs, const ARPPackage &rhs);

  protected:
    sniffarp *m_arp;
};
}

#endif // ARPPACKAGE_H
