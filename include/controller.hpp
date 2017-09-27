#ifndef PCAPCONTROLLER_H
#define PCAPCONTROLLER_H

#include <algorithm>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>

#include <pcap/pcap.h>

#include "interfaces/interfacepolicy.h"
#include "processors/processorpolicy.h"

namespace PCAP {

template <typename I, typename P> class Controller : private I, public P {
  public:
    Controller(const std::string &interfaceName)
        : I{interfaceName}, m_stopThread{true} {}

    using I::read_package;
    using I::write;
    using I::set_filter;

    Controller(const Controller &rhs) = delete;
    Controller(Controller &&rhs) = delete;
    Controller &operator=(const Controller &rhs) = delete;
    Controller &operator=(Controller &rhs) = delete;

    virtual ~Controller() {
        if (!m_stopThread) {
            stop();
        }
    }

    void start() {
        m_stopThread = false;
        m_f = std::async(std::launch::async, [this]() {
            while (!this->m_stopThread) {
                pcap_pkthdr header;
                const unsigned char *package = I::read_package(header);
                if (package) {
                    P::callback(package, header);
                }
            }
        });
    }

    void stop() {
        m_stopThread = true;
        m_f.get();
    }

  private:
    bool m_stopThread;
    std::future<void> m_f;
};
}

#endif // PCAPCONTROLLER_H
