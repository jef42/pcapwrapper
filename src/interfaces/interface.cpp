#include "../../include/interfaces/interface.h"

#include <cstring>
#include <stdexcept>

namespace PCAP {

Interface::Interface(const std::string &interfaceName)
    : InterfacePolicy{interfaceName}, m_handler{nullptr} {
    if (!openInterface(interfaceName)) {
        throw std::invalid_argument("wrong interface name");
    }
}

Interface::~Interface() noexcept {
    if (m_handler) {
        pcap_close(m_handler);
    }
}

bool Interface::openInterface(const std::string &netName) {
    const char *dev = netName.c_str();
    memset(m_errbuf, '\0', PCAP_ERRBUF_SIZE);

    m_handler = pcap_open_live(dev, 1518, 1, 1000, m_errbuf);
    return m_handler == nullptr ? false : true;
}

bool Interface::set_filter_impl(const std::string &filter) {
    if (m_handler != nullptr) {
        struct bpf_program fp;
        bpf_u_int32 net;
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

const unsigned char *Interface::read_package_impl(pcap_pkthdr &header) {
    return pcap_next(m_handler, &header);
}

int Interface::write_impl(const unsigned char *package, int len) {
    if (m_handler != nullptr) {
        return pcap_sendpacket(m_handler, package, len);
    }
    return -1;
}
}
