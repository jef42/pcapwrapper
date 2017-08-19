#ifndef SESSIONCONTROLLER_H
#define SESSIONCONTROLLER_H

#include <memory>
#include <vector>

#include "../../listeners/packagelistener.h"
#include "../packages/udppackage.h"
#include "../packages/tcppackage.h"
#include "session.h"

namespace PCAP {

class SessionController : public PackageListener<TCPPackage>,
                          public PackageListener<UDPPackage>
{
public:
    virtual ~SessionController() noexcept = default;

private:
    void receivedPackage(std::unique_ptr<TCPPackage> package) override;
    void receivedPackage(std::unique_ptr<UDPPackage> package) override;

    virtual void newSession(const Session&, std::unique_ptr<TCPPackage>) {}
    virtual void appendSession(const Session&, std::unique_ptr<TCPPackage>) {}
    virtual void finishedSession(const Session&) {}

    virtual void newSession(const Session&, std::unique_ptr<UDPPackage>) {}
    virtual void appendSession(const Session&, std::unique_ptr<UDPPackage>) {}

private:
    std::vector<Session> m_tcp_session;
    std::vector<Session> m_udp_session;
};

}


#endif
