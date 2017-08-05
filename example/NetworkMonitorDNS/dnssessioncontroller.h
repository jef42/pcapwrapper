#ifndef DNSSESSIONCONTROLLER_H
#define DNSSESSIONCONTROLLER_H

#include <vector>

#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/packages/udppackage.h>

#include "dnsworker.h"

class DNSSessionController : public PCAP::SessionController {
public:
    DNSSessionController(std::vector<PCAP::IpAddress>&& ignore_list);
    virtual void newSession(const PCAP::Session& session, std::unique_ptr<PCAP::UDPPackage> package) override;
    void finish();
private:
    std::vector<std::shared_ptr<DNSWorker>> m_workers;
    std::vector<PCAP::IpAddress> m_ignore_list;
};

#endif
