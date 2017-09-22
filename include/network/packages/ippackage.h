#ifndef IPPACKAGE_H
#define IPPACKAGE_H

#include <string>

#include "ethernetpackage.h"
#include "../sniff/sniffip.h"
#include "../addresses/ipaddress.h"

namespace PCAP {

class IPPackage : public EthernetPackage {
public:
    IPPackage(const unsigned char* p, unsigned int l, bool modify = false);

    IpAddress getSrcIp() const;
    IpAddress getDstIp() const;
    unsigned char getVHL() const;
    unsigned char getTOS() const;
    unsigned short getTotalLength() const;
    unsigned short getID() const;
    unsigned char getIpFlags() const;
    unsigned short getFragmentOffset() const;
    unsigned char getTTL() const;
    unsigned char getProtocol() const;

    void setDstIp(IpAddress ip);
    void setSrcIp(IpAddress ip);
    void setVHL(unsigned char value);
    void setTOS(unsigned char value);
    void setTotalLength(unsigned short length);
    void setID(unsigned short id);
    void setIpFlags(unsigned char flags);
    void setFragmentOffset(unsigned short fragment);
    void setTTL(unsigned char ttl);
    void setProtocol(unsigned char protocol);

    friend bool operator==(const IPPackage &lhs, const IPPackage &rhs);
    friend bool operator!=(const IPPackage &lhs, const IPPackage &rhs);

protected:
    sniffip* m_ip;
};

}

#endif
