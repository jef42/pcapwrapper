#ifndef UDPPACKAGE_H
#define UDPPACKAGE_H

#include <string>

#include "../sniff/sniffudp.h"
#include "ippackage.h"

namespace PCAP {

class UDPPackage : public IPPackage {
  public:
    UDPPackage(const unsigned char* p, unsigned int l, bool modify = false);

    unsigned short getSrcPort() const;
    unsigned short getDstPort() const;
    unsigned short getUDPLength() const;

    void setSrcPort(unsigned short src_port);
    void setDstPort(unsigned short dst_port);
    void setUDPLength(unsigned short length);

    void recalculateChecksums();

    const unsigned char* getData() const;
    unsigned int getDataLength() const;
    void appendData(unsigned char* data, int size);


    unsigned int getLength() const override;

  private:
    sniffudp* m_udp;
    unsigned char* m_data;
};

}

#endif
