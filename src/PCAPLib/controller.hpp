#ifndef PCAPCONTROLLER_H
#define PCAPCONTROLLER_H

#include <string>
#include <memory>
#include <future>
#include <map>
#include <mutex>
#include <algorithm>
#include <type_traits>
#include <unordered_map>

#include <pcap/pcap.h>

#include "processors/processorpolicy.h"
#include "interfaces/interfacepolicy.h"

namespace PCAP {

template <typename I, typename P>
class Controller : private I, public P {
  public:
    static std::shared_ptr<Controller> getController(const std::string& interface) {
        static std::unordered_map<std::string, std::shared_ptr<Controller<I,P>>> controllers;
        auto &controller_ptr = controllers[interface];
        if (!controller_ptr)
            controller_ptr = std::shared_ptr<Controller<I,P>>(new Controller<I,P>(interface));
        return controller_ptr;
    }

    using I::readPackage;
    using I::write;
    using I::setFilter;

    Controller(const Controller& rhs) = delete;
    Controller(Controller&& rhs) = delete;
    Controller& operator=(const Controller& rhs) = delete;
    Controller& operator=(Controller& rhs) = delete;

    virtual ~Controller() {
        if (!m_stopThread) {
            stop();
        }
    }

    void start() {
        m_stopThread = false;
        m_f = std::async([=]() {
            while (!m_stopThread) {
                pcap_pkthdr header;
                const unsigned char* package = I::readPackage(header);
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
    Controller(const std::string& interfaceName)
        :  I{interfaceName},
           m_stopThread{true}
    {}

    bool m_stopThread;
    std::future<void> m_f;
};

}

#endif // PCAPCONTROLLER_H
