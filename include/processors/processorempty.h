#ifndef PCAPPROCESSOREMPTY_H
#define PCAPPROCESSOREMPTY_H

#include "processorpolicy.h"

namespace PCAP {

class ProcessorEmpty : public PCAP::ProcessorPolicy {
  private:
    void callback_impl(const unsigned char *, const pcap_pkthdr &) override;
};
}

#endif
