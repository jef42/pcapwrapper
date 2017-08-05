#ifndef PCAPINTERFACEPOLICY_H
#define PCAPINTERFACEPOLICY_H

#include <string>

#include <pcap/pcap.h>

namespace PCAP {

class InterfacePolicy {
  public:
    InterfacePolicy(const std::string& name)
        : m_interface_name{name}
    {}

    const unsigned char* readPackage(pcap_pkthdr& header) {
        return read_package_impl(header);
    }

    int write(const unsigned char* package, int len) {
        return write_impl(package, len);
    }

    bool setFilter(const std::string& filter) {
        return set_filter_impl(filter);
    }

    virtual ~InterfacePolicy() {}
  protected:
    virtual const unsigned char* read_package_impl(pcap_pkthdr& header) = 0;
    virtual int write_impl(const unsigned char* package, int len) = 0;
    virtual bool set_filter_impl(const std::string& filter) = 0;

  protected:
    const std::string m_interface_name;
};

}

#endif
