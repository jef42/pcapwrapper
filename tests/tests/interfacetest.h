#ifndef INTERFACE_TEST_H
#define INTERFACE_TEST_H

#include <memory>
#include <pcap/pcap.h>
#include <pcapwrapper/interfaces/interfacepolicy.h>
#include <pcapwrapper/processors/processorsave.h>
#include <string>

class InterfaceTest : public PCAP::InterfacePolicy {
  public:
    explicit InterfaceTest(std::shared_ptr<PCAP::ProcessorSave> &processor)
        : InterfacePolicy(""), m_processor{processor} {}

  protected:
    const unsigned char *read_package_impl(pcap_pkthdr &header) {}
    bool set_filter_impl(const std::string &filter) {}

    int write_impl(const unsigned char *package, int len) {
        pcap_pkthdr header;
        header.caplen = len;
        header.len = len;
        m_processor->callback(package, header);
        return len;
    }

  private:
    std::shared_ptr<PCAP::ProcessorSave> m_processor;
};

#endif