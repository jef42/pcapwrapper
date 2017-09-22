#ifndef TCPPACKAGE_H
#define TCPPACKAGE_H

#include <string>

#include "../sniff/snifftcp.h"
#include "ippackage.h"

namespace PCAP {

class TCPPackage : public IPPackage {
  public:
    TCPPackage(const unsigned char* p, unsigned int l, bool modify = false);

    unsigned short getSrcPort() const;
    unsigned short getDstPort() const;
    unsigned int getSeqNr() const;
    unsigned int getAckNr() const;
    unsigned char getDataOffset() const;
    unsigned char getTcpFlags() const;
    unsigned short getWindowSize() const;
    unsigned short getUrgentPtr() const;

    void setSrcPort(unsigned short port);
    void setDstPort(unsigned short port);
    void setSeqNr(unsigned int nr);
    void setAckNr(unsigned int nr);
    void setDataOffset(unsigned char offset);
    void setTcpFlags(unsigned char flags);
    void setWindowSize(unsigned short size);
    void setUrgentPtr(unsigned short ptr);

    void recalculateChecksums();

    const unsigned char* getData() const; //return only tcp data
    unsigned int getDataLength() const;
    void appendData(unsigned char* data, int size);

    unsigned int getLength() const override; // return total length

    friend bool operator==(const TCPPackage &lhs, const TCPPackage &rhs);
    friend bool operator!=(const TCPPackage &lhs, const TCPPackage &rhs);

  private:
    snifftcp* m_tcp;
    snifftcpopt* m_tcp_opt;
    unsigned char* m_data;
};

}

#endif // TCPPACKAGE_H
