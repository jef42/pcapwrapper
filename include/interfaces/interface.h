#ifndef PCAPINTERFACE_H
#define PCAPINTERFACE_H

#include "../helpers/common.h"
#include "interfacepolicy.h"
#include <memory>
#include <pcap/pcap.h>
#include <string>

namespace PCAP {

class Interface : public InterfacePolicy {
  public:
    explicit Interface(const std::string &netName);
    ~Interface() noexcept;

    Interface(const Interface &rhs) = delete;
    Interface &operator=(const Interface &rhs) = delete;
    Interface(Interface &&rhs) = delete;
    Interface &operator=(Interface &&rhs) = delete;

  protected:
    const uchar *read_package_impl(pcap_pkthdr &header) override;
    int write_impl(const uchar *package, int len) override;
    bool set_filter_impl(const std::string &filter) override;

    bool open_interface(const std::string &netName);

    char m_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *m_handler;
};
}

#endif // PCAPINTERFACE_H
