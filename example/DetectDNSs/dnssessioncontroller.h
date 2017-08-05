#ifndef DNSSESSIONCONTROLLER_H
#define DNSSESSIONCONTROLLER_H

#include <vector>
#include <map>
#include <mutex>
#include <iostream>

#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "dnsentry.h"

class DNSSessionController : public PCAP::SessionController {
public:
    DNSSessionController(const std::vector<PCAP::IpAddress>& target);

    virtual void newSession(const PCAP::Session& session, std::unique_ptr<PCAP::UDPPackage> package) override;
    std::map<PCAP::IpAddress, std::vector<DNSEntry>> get_websites();

private:
    std::vector<PCAP::IpAddress> m_targets_ip;

    std::mutex m_websites_mutex;
    std::map<PCAP::IpAddress,std::vector<DNSEntry>> m_websites;
};


#endif
