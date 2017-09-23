#ifndef SESSIONCONTROLLER_H
#define SESSIONCONTROLLER_H

#include <memory>
#include <vector>

#include "../../listeners/packagelistener.h"
#include "../packages/tcppackage.h"
#include "../packages/udppackage.h"
#include "session.h"

namespace PCAP {

class SessionController : public PackageListener<TCPPackage>,
                          public PackageListener<UDPPackage> {
  public:
    virtual ~SessionController() noexcept = default;

  private:
    void receivedPackage(TCPPackage package) override;
    void receivedPackage(UDPPackage package) override;

    virtual void newSession(const Session &, TCPPackage) {}
    virtual void appendSession(const Session &, TCPPackage) {}
    virtual void finishedSession(const Session &) {}

    virtual void newSession(const Session &, UDPPackage) {}
    virtual void appendSession(const Session &, UDPPackage) {}

  private:
    std::vector<Session> m_tcp_session;
    std::vector<Session> m_udp_session;
};
}

#endif
