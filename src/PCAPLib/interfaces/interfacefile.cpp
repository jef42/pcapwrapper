#include "interfacefile.h"

#include <cstring>
#include <stdexcept>

namespace PCAP {

InterfaceFile::InterfaceFile(const std::string& filename)
    : InterfacePolicy{filename}
    , m_handler{nullptr} {
    if (!openInterface(filename)) {
        throw std::invalid_argument("file doesn't exist");
    }
}

InterfaceFile::~InterfaceFile() {
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
    return pcap_next(m_handler, &header);
}

int InterfaceFile::write_impl(const unsigned char *package, int len) {
    if (m_handler != nullptr) {
        return pcap_sendpacket(m_handler, package, len);
    }
    return -1;
}

}
