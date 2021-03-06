#include "dnssessioncontroller.h"

#include <algorithm>

DNSSessionController::DNSSessionController(
    std::vector<PCAP::IpAddress> &&ignore_list) noexcept
    : m_ignore_list{ignore_list} {}

void DNSSessionController::new_session(const PCAP::Session &,
                                      PCAP::UDPPackage package) {
    auto ip = package.get_src_ip();
    if (std::find(std::begin(m_ignore_list), std::end(m_ignore_list), ip) ==
        std::end(m_ignore_list)) {
        auto it = std::find_if(
            std::begin(m_workers), std::end(m_workers),
            [&ip](auto &worker) { return worker->get_src_ip() == ip; });

        if (it != std::end(m_workers)) {
            (*it)->new_session(package);
        } else {
            m_workers.push_back(std::make_shared<DNSWorker>(package));
        }
    }
}

void DNSSessionController::finish() {
    std::for_each(std::begin(m_workers), std::end(m_workers),
                  [](auto &worker) { worker->finish(); });
}
