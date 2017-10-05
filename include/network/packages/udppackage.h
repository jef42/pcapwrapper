#ifndef UDPPACKAGE_H
#define UDPPACKAGE_H

#include "../../helpers/common.h"
#include "../sniff/sniffudp.h"
#include "ippackage.h"
#include <string>

namespace PCAP {

class UDPPackage : public IPPackage {
  public:
    UDPPackage(const uchar *p, uint l, bool modify = false);

    ushort get_src_port() const;
    ushort get_dst_port() const;
    ushort get_udp_length() const;

    void set_src_port(ushort src_port);
    void set_dst_port(ushort dst_port);
    void set_udp_length(ushort length);

    void recalculate_checksums();

    const uchar *get_data() const;
    uint get_data_length() const;
    void append_data(uchar *data, int size);

    uint get_length() const override;

    friend bool operator==(const UDPPackage &lhs, const UDPPackage &rhs);
    friend bool operator!=(const UDPPackage &lhs, const UDPPackage &rhs);

  private:
    sniffudp *m_udp;
    uchar *m_data;
};
}

#endif
