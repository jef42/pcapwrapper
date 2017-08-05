#include "sessioncontroller.h"

#include <algorithm>

namespace PCAP {

SessionController::~SessionController(){}

void SessionController::receivedPackage(std::unique_ptr<TCPPackage> package) {
    const Session session(package->getSrcIp(), package->getDstIp(), package->getSrcPort(), package->getDstPort());
    bool is_finished = package->getFlags() & 0x01;
    if (std::find(m_tcp_session.begin(), m_tcp_session.end(), session) == m_tcp_session.end()) {
        m_tcp_session.push_back(session);
        return newSession(session, std::move(package));
    } else {
        appendSession(session, std::move(package));
    }
    if (is_finished) {
        m_tcp_session.erase(std::remove(m_tcp_session.begin(), m_tcp_session.end(), session), m_tcp_session.end());
        finishedSession(session);
    }
}

void SessionController::receivedPackage(std::unique_ptr<UDPPackage> package) {
    const Session session(package->getSrcIp(), package->getDstIp(), package->getSrcPort(), package->getDstPort());
    if (std::find(m_udp_session.begin(), m_udp_session.end(), session) == m_udp_session.end()) {
        m_udp_session.push_back(session);
        return newSession(session, std::move(package));
    } else {
        return appendSession(session, std::move(package));
    }
}

}
