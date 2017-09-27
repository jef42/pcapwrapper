#ifndef UDPPACKAGE_H
#define UDPPACKAGE_H

#include <string>

#include "../sniff/sniffudp.h"
#include "ippackage.h"

namespace PCAP {

class UDPPackage : public IPPackage {
  public:
    UDPPackage(const unsigned char *p, unsigned int l, bool modify = false);

    unsigned short get_src_port() const;
    unsigned short get_dst_port() const;
    unsigned short get_udp_length() const;

    void set_src_port(unsigned short src_port);
    void set_dst_port(unsigned short dst_port);
    void set_udp_length(unsigned short length);

    void recalculate_checksums();

    const unsigned char *get_data() const;
    unsigned int get_data_length() const;
    void append_data(unsigned char *data, int size);

    unsigned int get_length() const override;

    friend bool operator==(const UDPPackage &lhs, const UDPPackage &rhs);
    friend bool operator!=(const UDPPackage &lhs, const UDPPackage &rhs);

  private:
    sniffudp *m_udp;
    unsigned char *m_data;
};
}

#endif
