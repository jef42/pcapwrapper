#ifndef ETHERNETPACKAGE_H
#define ETHERNETPACKAGE_H

#include <string>

#include "../sniff/sniffethernet.h"
#include "basepackage.h"

#include "../addresses/macaddress.h"

namespace PCAP {

class EthernetPackage : public BasePackage {
  public:
    EthernetPackage(const uchar *p, uint l,
                    bool modify = false);

    MacAddress get_src_mac() const;
    MacAddress get_dst_mac() const;
    ushort get_ether_type() const;

    void set_src_mac(MacAddress mac);
    void set_dst_mac(MacAddress mac);
    void set_ether_type(ushort type);

    friend bool operator==(const EthernetPackage &lhs,
                           const EthernetPackage &rhs);
    friend bool operator!=(const EthernetPackage &lhs,
                           const EthernetPackage &rhs);

  protected:
    sniffethernet *m_ethernet;
};
}

#endif
