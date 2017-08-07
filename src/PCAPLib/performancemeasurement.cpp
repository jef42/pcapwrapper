#include "performancemeasurement.h"

namespace PCAP {
namespace Logging {


std::chrono::milliseconds::rep get_time() {
    auto duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

}
}
