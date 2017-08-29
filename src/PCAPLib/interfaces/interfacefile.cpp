#include "interfacefile.h"

#include <cstring>
#include <stdexcept>
#include <chrono>
#include <thread>

namespace PCAP {

InterfaceFile::InterfaceFile(const std::string& filename)
    : InterfacePolicy{filename}
    , m_handler{nullptr} {
    if (!openInterface(filename)) {
        throw std::invalid_argument("file doesn't exist");
    }
}

InterfaceFile::~InterfaceFile() noexcept {
    if (m_handler) {
        pcap_close(m_handler);
    }
}

bool InterfaceFile::openInterface(const std::string& filename) {
    const char* dev = filename.c_str();
    memset(m_errbuf, '\0', PCAP_ERRBUF_SIZE);

    m_handler = pcap_open_offline(dev, m_errbuf);
    if (m_handler == nullptr) {
        return false;
    }
    return true;
}

bool InterfaceFile::set_filter_impl(const std::string&) {
    return false;
}

const unsigned char* InterfaceFile::read_package_impl(pcap_pkthdr &header) {
    static auto cr_time = std::chrono::duration_cast< std::chrono::milliseconds >(
                            std::chrono::system_clock::now().time_since_epoch());;

    auto tmp = pcap_next(m_handler, &header);
    if (tmp) {
        std::chrono::milliseconds new_time{header.ts.tv_sec * 1000 + header.ts.tv_usec / 1000};
        std::this_thread::sleep_for(new_time - cr_time);
        cr_time = new_time;
    }
    return tmp;
}

int InterfaceFile::write_impl(const unsigned char *package, int len) {
    if (m_handler != nullptr) {
        return pcap_sendpacket(m_handler, package, len);
    }
    return -1;
}

}
