#include "../../include/interfaces/interfacethreadsafe.h"

namespace PCAP {

std::mutex InterfaceThreadSafe::m_mutex;

InterfaceThreadSafe::InterfaceThreadSafe(const std::string &name)
    : Interface{name} {}

int InterfaceThreadSafe::write_impl(const uchar *package, int len) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return Interface::write_impl(package, len);
}
}
