#ifndef PCAPINTERFACEPOLICY_H
#define PCAPINTERFACEPOLICY_H

#include "../helpers/common.h"
#include <pcap/pcap.h>
#include <string>

namespace PCAP {

class InterfacePolicy {
  public:
    explicit InterfacePolicy(const std::string &name)
        : m_interface_name{name} {}

    const uchar *read_package(pcap_pkthdr &header) {
        return read_package_impl(header);
    }

    int write(const uchar *package, int len) {
        return write_impl(package, len);
    }

    bool set_filter(const std::string &filter) {
        return set_filter_impl(filter);
    }

    virtual ~InterfacePolicy() noexcept = default;

  protected:
    virtual const uchar *read_package_impl(pcap_pkthdr &header) = 0;
    virtual int write_impl(const uchar *package, int len) = 0;
    virtual bool set_filter_impl(const std::string &filter) = 0;

  protected:
    const std::string m_interface_name;
};
}

#endif
