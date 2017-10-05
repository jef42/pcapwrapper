#ifndef ICMPPACKAGE_H
#define ICMPPACKAGE_H

#include "../../helpers/common.h"
#include "../sniff/snifficmp.h"
#include "ippackage.h"
#include <string>

namespace PCAP {

class ICMPPackage : public IPPackage {
  public:
    ICMPPackage(const uchar *p, uint l, bool modify = false);

    uchar get_type() const;
    uchar get_code() const;

    void set_type(uchar type);
    void set_code(uchar code);

    void recalculate_checksums();

    const uchar *get_data() const;
    uint get_data_length() const;
    void append_data(uchar *data, int size);

    uint get_length() const override;

    friend bool operator==(const ICMPPackage &lhs, const ICMPPackage &rhs);
    friend bool operator!=(const ICMPPackage &lhs, const ICMPPackage &rhs);

  protected:
    snifficmp *m_icmp;
    uchar *m_data;
};
}

#endif // ICMPPACKAGE_H
