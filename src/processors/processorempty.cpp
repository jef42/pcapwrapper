#include "../../include/processors/processorempty.h"

namespace PCAP {

    void ProcessorEmpty::callback_impl(const unsigned char *, const pcap_pkthdr &){}

}
