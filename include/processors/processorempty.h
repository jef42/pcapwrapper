#ifndef PCAPPROCESSOREMPTY_H
#define PCAPPROCESSOREMPTY_H

#include "../helpers/common.h"
#include "processorpolicy.h"

namespace PCAP {

class ProcessorEmpty : public PCAP::ProcessorPolicy {
  private:
    void callback_impl(const uchar *, const pcap_pkthdr &) override;
};
}

#endif
