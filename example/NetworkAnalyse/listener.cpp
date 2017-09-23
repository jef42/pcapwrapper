#include "listener.h"

#include <thread>

Listener::Listener(const PCAP::IpAddress &netmask) : m_netmask{netmask} {}

void Listener::inc_count(PCAP::IpAddress ip) {
    std::lock_guard<std::mutex> lock(m_lock);
    auto it = m_counts.find(ip);
    if (it != m_counts.end()) {
        it->second.fetch_add(1);
        return;
    }
    m_counts.emplace(ip, 0);
}

std::vector<std::pair<PCAP::IpAddress, unsigned int>> Listener::get_count() {
    std::lock_guard<std::mutex> lock(m_lock);
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> result;
    for (auto &v : m_counts) {
        result.emplace_back(v.first, v.second.load());
    }
    return result;
}
