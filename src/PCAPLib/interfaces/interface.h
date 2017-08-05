#ifndef PCAPINTERFACE_H
#define PCAPINTERFACE_H

#include <string>
#include <memory>

#include <pcap/pcap.h>

#include "interfacepolicy.h"


namespace PCAP {

class Interface : public InterfacePolicy {
  public:
    Interface(const std::string& netName);
    virtual ~Interface();

    Interface(const Interface& rhs) = delete;
    Interface& operator=(const Interface& rhs) = delete;
    Interface(Interface&& rhs) = delete;
    Interface& operator=(Interface&& rhs) = delete;

  protected:
    virtual const unsigned char* read_package_impl(pcap_pkthdr& header);
    virtual int write_impl(const unsigned char* package, int len);
    virtual bool set_filter_impl(const std::string& filter);

    bool openInterface(const std::string& netName);

    char m_errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 m_mask;
    bpf_u_int32 m_net;

    pcap_t* m_handler;
};

}

#endif // PCAPINTERFACE_H
