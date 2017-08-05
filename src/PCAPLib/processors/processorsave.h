#ifndef PCAPPROCESSORSAVE_H
#define PCAPPROCESSORSAVE_H

#include <string>
#include <vector>
#include <mutex>
#include <utility>

#include "processorpolicy.h"

namespace PCAP {

class ProcessorSave : public ProcessorPolicy
{
public:
    virtual ~ProcessorSave();

    bool save(const std::string& filename);
private:
    virtual void callback_impl(const unsigned char *package, const pcap_pkthdr &header);

    const std::string m_filename;
    std::mutex m_mutex;

    using Package = std::pair<pcap_pkthdr, unsigned char*>;
    std::vector<Package> m_packages;
};

}


#endif
