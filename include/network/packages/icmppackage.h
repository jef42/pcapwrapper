#ifndef ICMPPACKAGE_H
#define ICMPPACKAGE_H

#include <string>

#include "../sniff/snifficmp.h"
#include "ippackage.h"

namespace PCAP {

class ICMPPackage : public IPPackage {
  public:
    ICMPPackage(const unsigned char *p, unsigned int l, bool modify = false);

    unsigned char get_type() const;
    unsigned char get_code() const;

    void set_type(unsigned char type);
    void set_code(unsigned char code);

    void recalculate_checksums();

    const unsigned char *get_data() const;
    unsigned int get_data_length() const;
    void append_data(unsigned char *data, int size);

    unsigned int get_length() const override;

    friend bool operator==(const ICMPPackage &lhs, const ICMPPackage &rhs);
    friend bool operator!=(const ICMPPackage &lhs, const ICMPPackage &rhs);

  protected:
    snifficmp *m_icmp;
    unsigned char *m_data;
};
}

#endif // ICMPPACKAGE_H
