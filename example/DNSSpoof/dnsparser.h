#ifndef DNSPARSER_H
#define DNSPARSER_H

#include <vector>

#include <pcapwrapper/helpers/constants.h>
#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>

#include "dnsframe.h"

class DNSParser {
  public:
    DNSParser(const unsigned char *package, int length);

    void build();
    unsigned char *getPackage() const;
    unsigned int getLength() const;

  private:
    unsigned char m_package[snap_len];
    int m_index;

  public:
    PCAP::sniffethernet *m_ethernet;
    PCAP::sniffip *m_ip;
    PCAP::sniffudp *m_udp;
    sniffdns_question *m_question;
    sniffdns_query *m_query;
    std::vector<sniffdns_answer *> m_answers;
};

#endif // DNSPARSER_H
