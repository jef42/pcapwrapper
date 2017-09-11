#ifndef ICMPPACKAGE_H
#define ICMPPACKAGE_H

#include <string>

#include "../sniff/snifficmp.h"
#include "ippackage.h"

namespace PCAP {

class ICMPPackage : public IPPackage {
  public:
    ICMPPackage(const unsigned char* p, unsigned int l, bool modify = false);

    unsigned char getType() const;
    unsigned char getCode() const;

    void setType(unsigned char type);
    void setCode(unsigned char code);

    void recalculateChecksums();

    const unsigned char* getData() const;
    unsigned int getDataLength() const;
    void appendData(unsigned char* data, int size);

    unsigned int getLength() const override;

    friend bool operator==(const ICMPPackage &lhs, const ICMPPackage &rhs);
    friend bool operator!=(const ICMPPackage &lhs, const ICMPPackage &rhs);

  protected:
    snifficmp* m_icmp;
    unsigned char* m_data;
};

}

#endif // ICMPPACKAGE_H
