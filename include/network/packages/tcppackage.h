#ifndef TCPPACKAGE_H
#define TCPPACKAGE_H

#include <string>

#include "../sniff/snifftcp.h"
#include "ippackage.h"

namespace PCAP {

class TCPPackage : public IPPackage {
  public:
    TCPPackage(const uchar *p, uint l, bool modify = false);

    ushort get_src_port() const;
    ushort get_dst_port() const;
    uint get_seq_nr() const;
    uint get_ack_nr() const;
    uchar get_data_offset() const;
    uchar get_tcp_flags() const;
    ushort get_window_size() const;
    ushort get_urgent_ptr() const;

    void set_src_port(ushort port);
    void set_dst_port(ushort port);
    void set_seq_nr(uint nr);
    void set_ack_nr(uint nr);
    void set_data_offset(uchar offset);
    void set_tcp_flags(uchar flags);
    void set_window_size(ushort size);
    void set_urgent_ptr(ushort ptr);

    void recalculate_checksums();

    const uchar *get_data() const; // return only tcp data
    uint get_data_length() const;
    void append_data(uchar *data, int size);

    uint get_length() const override; // return total length

    friend bool operator==(const TCPPackage &lhs, const TCPPackage &rhs);
    friend bool operator!=(const TCPPackage &lhs, const TCPPackage &rhs);

  private:
    snifftcp *m_tcp;
    uchar *m_data;
};
}

#endif // TCPPACKAGE_H
