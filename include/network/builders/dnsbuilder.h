#ifndef DNSBUILDER_H
#define DNSBUILDER_H

#include "../../helpers/common.h"
#include "../sniff/sniffdns.h"
#include "../sniff/sniffethernet.h"
#include "../sniff/sniffip.h"
#include "../sniff/sniffudp.h"
#include <string>

namespace PCAP {
namespace PCAPBuilder {

sniffdns_question create_dns_question(ushort answers, const PCAP::uchar *data,
                                      ushort size);
sniffdns_query create_dns_query(const PCAP::uchar *website);
sniffdns_answer create_dns_answer(const std::string &spoof_ip);

class DNSBuilder {
  public:
    DNSBuilder();

    void operator<<(PCAP::sniffethernet ethernet);
    void operator<<(PCAP::sniffip ip);
    void operator<<(PCAP::sniffudp udp);
    void operator<<(PCAP::sniffdns_question question);
    void operator<<(PCAP::sniffdns_query query);
    void operator<<(PCAP::sniffdns_answer answer);

    void build();
    PCAP::uchar *get_package() const;
    PCAP::uint get_length() const;

  private:
    PCAP::uchar m_package[snap_len];
    PCAP::uint m_index;

    PCAP::sniffethernet *m_ethernet;
    PCAP::sniffip *m_ip;
    PCAP::sniffudp *m_udp;
    PCAP::sniffdns_question *m_question;
    PCAP::sniffdns_query *m_query;
    PCAP::sniffdns_answer *m_answer;
};
}
}

#endif