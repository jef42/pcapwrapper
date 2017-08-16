#ifndef PCAPINTERFACEFILE_H
#define PCAPINTERFACEFILE_H

#include <string>
#include <memory>

#include <pcap/pcap.h>

#include "interfacepolicy.h"

namespace PCAP {

class InterfaceFile : public InterfacePolicy {
public:
    InterfaceFile(const std::string& filename);
    virtual ~InterfaceFile() noexcept;

    InterfaceFile(const InterfaceFile& rhs) = delete;
    InterfaceFile& operator=(const InterfaceFile& rhs) = delete;
    InterfaceFile(InterfaceFile&& rhs) = delete;
    InterfaceFile& operator=(InterfaceFile&& rhs) = delete;

  protected:
    virtual const unsigned char* read_package_impl(pcap_pkthdr& header);
    virtual int write_impl(const unsigned char* package, int len);
    virtual bool set_filter_impl(const std::string& filter);

    bool openInterface(const std::string& netName);

    char m_errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* m_handler;
};

}

#endif
