#include "../../../include/network/sessions/sessioncontroller.h"

#include <algorithm>

namespace PCAP {

void SessionController::receive_package(TCPPackage package) {
    const Session session(package.get_src_ip(), package.get_dst_ip(),
                          package.get_src_port(), package.get_dst_port());
    bool is_finished = package.get_tcp_flags() & 0x01;
    if (std::find(m_tcp_session.begin(), m_tcp_session.end(), session) ==
        m_tcp_session.end()) {
        m_tcp_session.push_back(session);
        return new_session(session, package);
    } else {
        append_session(session, package);
    }
    if (is_finished) {
        m_tcp_session.erase(
            std::remove(m_tcp_session.begin(), m_tcp_session.end(), session),
            m_tcp_session.end());
        finished_session(session);
    }
}

void SessionController::receive_package(UDPPackage package) {
    const Session session(package.get_src_ip(), package.get_dst_ip(),
                          package.get_src_port(), package.get_dst_port());
    if (std::find(m_udp_session.begin(), m_udp_session.end(), session) ==
        m_udp_session.end()) {
        m_udp_session.push_back(session);
        return new_session(session, package);
    } else {
        return append_session(session, package);
    }
}
}
