#ifndef COOKIESESSIONCONTROLLER_H
#define COOKIESESSIONCONTROLLER_H

#include <vector>

#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

#include "cookieworker.h"

class CookieSessionController : public PCAP::SessionController {
public:
    CookieSessionController(const PCAP::IpAddress& mask, std::vector<PCAP::IpAddress>&& ignore_ip);
    virtual void receivedPackage(std::unique_ptr<PCAP::TCPPackage> package) override;
    void finish();
private:
    PCAP::IpAddress m_mask;

    std::vector<std::shared_ptr<CookieWorker>> m_workers;
    std::vector<PCAP::IpAddress> m_ignore_ips;
};

#endif
