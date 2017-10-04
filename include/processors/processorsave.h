#ifndef PCAPPROCESSORSAVE_H
#define PCAPPROCESSORSAVE_H

#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "processorpolicy.h"

namespace PCAP {

class ProcessorSave : public ProcessorPolicy {
  public:
    virtual ~ProcessorSave() noexcept;

    bool save(const std::string &filename);

  private:
    void callback_impl(const uchar *package,
                       const pcap_pkthdr &header) override;

    std::mutex m_mutex;

    using Package = std::pair<pcap_pkthdr, uchar *>;
    std::vector<Package> m_packages;
};
}

#endif
