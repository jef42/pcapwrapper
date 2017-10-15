#ifndef DNSPARSER_H
#define DNSPARSER_H

#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/helpers/constants.h>
#include <pcapwrapper/network/sniff/sniffdns.h>
#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>
#include <string>
#include <vector>

PCAP::sniffethernet create_ethernet(const std::string &src_mac,
                                    const std::string &dst_mac);
PCAP::sniffip create_ip(const std::string &src_ip, const std::string &dst_ip);
PCAP::sniffudp create_udp(ushort src_port, ushort dst_port);

class DNSParser {
  public:
    DNSParser(const PCAP::uchar *package, int length);

    void build();
    PCAP::uchar *get_package() const;
    PCAP::uint get_length() const;

  private:
    PCAP::uchar m_package[snap_len];
    int m_index;

  public:
    PCAP::sniffethernet *m_ethernet;
    PCAP::sniffip *m_ip;
    PCAP::sniffudp *m_udp;
    PCAP::sniffdns_question *m_question;
    PCAP::sniffdns_query *m_query;
    std::vector<PCAP::sniffdns_answer *> m_answers;
};

#endif // DNSPARSER_H
