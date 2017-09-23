#ifndef PCAPINTERFACEFILE_H
#define PCAPINTERFACEFILE_H

#include <chrono>
#include <string>

#include <pcap/pcap.h>

#include "interfacepolicy.h"

namespace PCAP {

class InterfaceFile : public InterfacePolicy {
  public:
    explicit InterfaceFile(const std::string &filename);
    ~InterfaceFile() noexcept;

    InterfaceFile(const InterfaceFile &rhs) = delete;
    InterfaceFile &operator=(const InterfaceFile &rhs) = delete;
    InterfaceFile(InterfaceFile &&rhs) = delete;
    InterfaceFile &operator=(InterfaceFile &&rhs) = delete;

  protected:
    const unsigned char *read_package_impl(pcap_pkthdr &header) override;
    int write_impl(const unsigned char *package, int len) override;
    bool set_filter_impl(const std::string &filter) override;

    bool openInterface(const std::string &netName);

    char m_errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *m_handler;
    std::chrono::milliseconds m_cr_time;
};
}

#endif
