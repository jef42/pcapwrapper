#include "maclistener.h"

#include <thread>

namespace PCAP {
namespace PCAPHelper {

MacListener::MacListener(const PCAP::IpAddress& ip)
    : m_ip{ip},
    m_founded{false} {

}

void MacListener::receivedPackage(std::unique_ptr<PCAP::ARPPackage> package) {
    if (package->getSrcIp() == m_ip) {
        m_result = package->getSrcMac();
        m_founded = true;
    }
}

PCAP::MacAddress MacListener::getMac() const noexcept {
    while (!m_founded) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);
    }
    return m_result;
}

}
}
