#include "../../../include/helpers/listeners/maclistener.h"

#include <thread>

namespace PCAP {
namespace PCAPHelper {

MacListener::MacListener(const PCAP::IpAddress &ip)
    : m_ip{ip}, m_founded{false} {}

void MacListener::receive_package(PCAP::ARPPackage package) {
    if (package.get_src_ip() == m_ip) {
        m_result = package.get_src_mac();
        m_founded = true;
    }
}

PCAP::MacAddress MacListener::get_mac() const noexcept {
    while (!m_founded) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);
    }
    return m_result;
}
}
}
