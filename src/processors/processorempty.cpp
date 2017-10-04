#include "../../include/processors/processorempty.h"

namespace PCAP {

void ProcessorEmpty::callback_impl(const uchar *, const pcap_pkthdr &) {
}
}
