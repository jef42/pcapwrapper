#include "../../include/interfaces/interfacefile.h"

#include <cstring>
#include <stdexcept>
#include <thread>

namespace PCAP {

InterfaceFile::InterfaceFile(const std::string &filename)
    : InterfacePolicy{filename}, m_handler{nullptr}, m_cr_time{0} {
    if (!open_interface(filename)) {
        throw std::invalid_argument("file doesn't exist");
    }
}

InterfaceFile::~InterfaceFile() noexcept {
    if (m_handler) {
        pcap_close(m_handler);
    }
}

bool InterfaceFile::open_interface(const std::string &filename) {
    const char *dev = filename.c_str();
    memset(m_errbuf, '\0', PCAP_ERRBUF_SIZE);

    m_handler = pcap_open_offline(dev, m_errbuf);
    if (m_handler == nullptr) {
        return false;
    }
    return true;
}

bool InterfaceFile::set_filter_impl(const std::string &filter) {
    if (m_handler != nullptr) {
        struct bpf_program fp;
        bpf_u_int32 net = 0;
        if (pcap_compile(m_handler, &fp, filter.c_str(), 0, net) == -1) {
            return false;
        }
        if (pcap_setfilter(m_handler, &fp) == -1) {
            return false;
        }
        return true;
    }
    return false;
}

const unsigned char *InterfaceFile::read_package_impl(pcap_pkthdr &header) {
    auto tmp = pcap_next(m_handler, &header);
    if (tmp) {
        std::chrono::milliseconds new_time{header.ts.tv_sec * 1000 +
                                           header.ts.tv_usec / 1000};
        if (m_cr_time == std::chrono::milliseconds{0})
            m_cr_time = new_time;
        std::this_thread::sleep_for(new_time - m_cr_time);
        m_cr_time = new_time;
    }
    return tmp;
}

int InterfaceFile::write_impl(const unsigned char *, int) { return -1; }
}
