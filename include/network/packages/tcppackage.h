#ifndef TCPPACKAGE_H
#define TCPPACKAGE_H

#include <string>

#include "../sniff/snifftcp.h"
#include "ippackage.h"

namespace PCAP {

class TCPPackage : public IPPackage {
  public:
    TCPPackage(const unsigned char *p, unsigned int l, bool modify = false);

    unsigned short get_src_port() const;
    unsigned short get_dst_port() const;
    unsigned int get_seq_nr() const;
    unsigned int get_ack_nr() const;
    unsigned char get_data_offset() const;
    unsigned char get_tcp_flags() const;
    unsigned short get_window_size() const;
    unsigned short get_urgent_ptr() const;

    void set_src_port(unsigned short port);
    void set_dst_port(unsigned short port);
    void set_seq_nr(unsigned int nr);
    void set_ack_nr(unsigned int nr);
    void set_data_offset(unsigned char offset);
    void set_tcp_flags(unsigned char flags);
    void set_window_size(unsigned short size);
    void set_urgent_ptr(unsigned short ptr);

    void recalculate_checksums();

    const unsigned char *get_data() const; // return only tcp data
    unsigned int get_data_length() const;
    void append_data(unsigned char *data, int size);

    unsigned int get_length() const override; // return total length

    friend bool operator==(const TCPPackage &lhs, const TCPPackage &rhs);
    friend bool operator!=(const TCPPackage &lhs, const TCPPackage &rhs);

  private:
    snifftcp *m_tcp;
    unsigned char *m_data;
};
}

#endif // TCPPACKAGE_H
