#ifndef PCAPPROCESSORPOLICY_H
#define PCAPPROCESSORPOLICY_H

#include <pcap/pcap.h>

namespace PCAP {

class ProcessorPolicy {
  public:
    void callback(const unsigned char *package, const pcap_pkthdr &header) {
        return callback_impl(package, header);
    }

    virtual ~ProcessorPolicy() {}
  protected:
    virtual void callback_impl(const unsigned char *package, const pcap_pkthdr &header) = 0;
};

}

#endif
