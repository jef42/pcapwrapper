#ifndef DNSSESSIONCONTROLLER_H
#define DNSSESSIONCONTROLLER_H

#include <vector>

#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/sessions/sessioncontroller.h>

#include "dnsworker.h"

class DNSSessionController : public PCAP::SessionController {
  public:
    explicit DNSSessionController(
        std::vector<PCAP::IpAddress> &&ignore_list) noexcept;
    virtual void new_session(const PCAP::Session &session,
                            PCAP::UDPPackage package) override;
    void finish();

  private:
    std::vector<std::shared_ptr<DNSWorker>> m_workers;
    std::vector<PCAP::IpAddress> m_ignore_list;
};

#endif
