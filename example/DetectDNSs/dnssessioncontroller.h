#ifndef DNSSESSIONCONTROLLER_H
#define DNSSESSIONCONTROLLER_H

#include <iostream>
#include <map>
#include <mutex>
#include <vector>

#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/sessions/sessioncontroller.h>

#include "dnsentry.h"

class DNSSessionController : public PCAP::SessionController {
  public:
    DNSSessionController(const std::vector<PCAP::IpAddress> &target);

    void new_session(const PCAP::Session &session,
                    PCAP::UDPPackage package) override;
    std::map<PCAP::IpAddress, std::vector<DNSEntry>> get_websites();

  private:
    std::vector<PCAP::IpAddress> m_targets_ip;

    std::mutex m_websites_mutex;
    std::map<PCAP::IpAddress, std::vector<DNSEntry>> m_websites;
};

#endif
