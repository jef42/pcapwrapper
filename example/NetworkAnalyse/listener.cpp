#include "listener.h"

#include <thread>

Listener::Listener(const PCAP::IpAddress& ip)
    : m_ip{ip}
{}

void Listener::inc_count() {
    std::lock_guard<std::mutex> lock(m_lock);
    ++m_count;
}

unsigned long Listener::get_count() {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_count;
}
