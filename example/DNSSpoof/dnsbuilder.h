#ifndef DNSBUILDER_H
#define DNSBUILDER_H

#include <string>

#include <pcapwrapper/network/sniff/sniffethernet.h>
#include <pcapwrapper/network/sniff/sniffip.h>
#include <pcapwrapper/network/sniff/sniffudp.h>
#include <pcapwrapper/helpers/constants.h>

#include "dnsframe.h"

PCAP::sniffethernet create_ethernet(const std::string& src_mac, const std::string& dst_mac);
PCAP::sniffip create_ip(const std::string& src_ip, const std::string& dst_ip);
PCAP::sniffudp create_udp(unsigned short src_port, unsigned short dst_port);
sniffdns_question create_dns_question(unsigned short answers, const unsigned char* data, unsigned short size);
sniffdns_query create_dns_query(const unsigned char* website);
sniffdns_answer create_dns_answer(const std::string& spoof_ip);

bool setIp(unsigned char* ip, const std::string& ip_value, int base);
bool setMac(unsigned char* addr, const std::string& ethernet_value, int base);

class DNSBuilder {
public:
    DNSBuilder();

    void operator <<(PCAP::sniffethernet ethernet);
    void operator <<(PCAP::sniffip ip);
    void operator <<(PCAP::sniffudp udp);
    void operator <<(sniffdns_question question);
    void operator <<(sniffdns_query query);
    void operator <<(sniffdns_answer answer);

    void build();
    unsigned char* getPackage() const;
    unsigned int getLength() const;
private:
    unsigned char m_package[SNAP_LEN];
    unsigned int m_index;
    PCAP::sniffethernet* m_ethernet;
    PCAP::sniffip *m_ip;
    PCAP::sniffudp *m_udp;
    sniffdns_question *m_question;
    sniffdns_query *m_query;
    sniffdns_answer *m_answer;
};

#endif // DNSBUILDER_H
