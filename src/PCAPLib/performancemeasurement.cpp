#include "performancemeasurement.h"

namespace PCAP {
namespace Logging {


unsigned long get_time() {
    return std::chrono::system_clock::now().time_since_epoch().count();
}

}
}
