#include "httpsessioncontroller.h"

#include <algorithm>
#include <iostream>

#include <pcapwrapper/helpers/helper.h>

HTTPSessionController::HTTPSessionController(const PCAP::IpAddress& mask, std::vector<PCAP::IpAddress> &&ignore_ips)
    : m_mask{mask}
    , m_ignore_ips{ignore_ips}
{
}

void HTTPSessionController::receivedPackage(PCAP::TCPPackage package) {
    auto src_ip = package.getSrcIp();
    if (m_mask != (m_mask & src_ip)) {
        return; //not in the same network
    }

    if (std::find(std::begin(m_ignore_ips), std::end(m_ignore_ips), src_ip) == std::end(m_ignore_ips)) {
        auto it = std::find_if(std::begin(m_workers), std::end(m_workers), [&src_ip](auto &a){ return a->get_src_ip() == src_ip; });
        if (it != std::end(m_workers)) {
            (*it)->new_package(package);
        }
        else {
            m_workers.push_back(std::make_shared<HTTPWorker>(package));
        }
    }
}

void HTTPSessionController::finish() {
	std::for_each(std::begin(m_workers), std::end(m_workers), [](auto& worker) { worker->finish();});
}
