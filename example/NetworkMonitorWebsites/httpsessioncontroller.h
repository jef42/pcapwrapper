#ifndef HTTPSESSIONCONTROLLER_H
#define HTTPSESSIONCONTROLLER_H

#include <vector>

#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/packages/tcppackage.h>

#include "httpworker.h"

class HTTPSessionController : public PCAP::SessionController {
public:
    HTTPSessionController(const PCAP::IpAddress& mask, std::vector<PCAP::IpAddress>&& ignore_websites);
    virtual void receivedPackage(PCAP::TCPPackage package) override;
    void finish();
private:
    PCAP::IpAddress m_mask;

    std::vector<std::shared_ptr<HTTPWorker>> m_workers;
    std::vector<PCAP::IpAddress> m_ignore_ips;
};

#endif
