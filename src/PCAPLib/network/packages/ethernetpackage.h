#ifndef ETHERNETPACKAGE_H
#define ETHERNETPACKAGE_H

#include <string>

#include "../sniff/sniffethernet.h"
#include "basepackage.h"

#include "../addresses/macaddress.h"

namespace PCAP {

class EthernetPackage : public BasePackage {
public:
    EthernetPackage(const unsigned char* p, unsigned int l, bool modify = false);

    MacAddress getSrcMac() const;
    MacAddress getDstMac() const;
    unsigned short getEtherType() const;

    void setSrcMac(MacAddress mac);
    void setDstMac(MacAddress mac);
    void setEtherType(unsigned short type);


protected:
    sniffethernet* m_ethernet;
};

}

#endif
