#include "dnssessioncontroller.h"

#include <algorithm>
#include <iostream>

DNSSessionController::DNSSessionController(std::vector<PCAP::IpAddress>&& ignore_list)
    : m_ignore_list{ignore_list}{

}

void DNSSessionController::newSession(const PCAP::Session&, std::unique_ptr<PCAP::UDPPackage> package) {
	auto ip = package->getSrcIp();
    if (std::find(std::begin(m_ignore_list), std::end(m_ignore_list), ip) == std::end(m_ignore_list)) {
        auto it = std::find_if(std::begin(m_workers), std::end(m_workers), [&ip](auto& worker){ return worker->get_src_ip() == ip; });

        if (it != std::end(m_workers)) {
            (*it)->new_session(std::move(package));
        }
        else {
            m_workers.push_back(std::make_shared<DNSWorker>(std::move(package)));
        }
    }
}

void DNSSessionController::finish() {
	std::for_each(std::begin(m_workers), std::end(m_workers), [](auto& worker) { worker->finish(); });
}
