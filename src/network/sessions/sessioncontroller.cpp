#include "../../../include/network/sessions/sessioncontroller.h"

#include <algorithm>

namespace PCAP {

void SessionController::receivedPackage(TCPPackage package) {
    const Session session(package.getSrcIp(), package.getDstIp(),
                          package.getSrcPort(), package.getDstPort());
    bool is_finished = package.getTcpFlags() & 0x01;
    if (std::find(m_tcp_session.begin(), m_tcp_session.end(), session) ==
        m_tcp_session.end()) {
        m_tcp_session.push_back(session);
        return newSession(session, package);
    } else {
        appendSession(session, package);
    }
    if (is_finished) {
        m_tcp_session.erase(
            std::remove(m_tcp_session.begin(), m_tcp_session.end(), session),
            m_tcp_session.end());
        finishedSession(session);
    }
}

void SessionController::receivedPackage(UDPPackage package) {
    const Session session(package.getSrcIp(), package.getDstIp(),
                          package.getSrcPort(), package.getDstPort());
    if (std::find(m_udp_session.begin(), m_udp_session.end(), session) ==
        m_udp_session.end()) {
        m_udp_session.push_back(session);
        return newSession(session, package);
    } else {
        return appendSession(session, package);
    }
}
}
