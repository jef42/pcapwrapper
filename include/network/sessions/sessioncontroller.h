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
    void receive_package(TCPPackage package) override;
    void receive_package(UDPPackage package) override;

    virtual void new_session(const Session &, TCPPackage) {}
    virtual void append_session(const Session &, TCPPackage) {}
    virtual void finished_session(const Session &) {}

    virtual void new_session(const Session &, UDPPackage) {}
    virtual void append_session(const Session &, UDPPackage) {}

  private:
    std::vector<Session> m_tcp_session;
    std::vector<Session> m_udp_session;
};
}

#endif
