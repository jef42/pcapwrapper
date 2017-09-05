#include "../../include/processors/processorsave.h"

#include <cstring>
#include <pcap/pcap.h>

namespace PCAP {

ProcessorSave::~ProcessorSave() noexcept
{
    for (auto package : m_packages) {
        delete[] package.second;
    }
    m_packages.clear();
}

bool ProcessorSave::save(const std::string& filename)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dumper = pcap_dump_open(pd, filename.c_str());
    for (auto package : m_packages) {
        pcap_dump((unsigned char*)dumper, &package.first, package.second);
    }
    pcap_dump_close(dumper);
    pcap_close(pd);
    return true;
}

void ProcessorSave::callback_impl(const unsigned char *package, const pcap_pkthdr &header)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    unsigned char* tmp = new unsigned char[header.len];
    memcpy(tmp, package, header.len);
    m_packages.push_back(std::make_pair(header, tmp));
}

}
