#ifndef DSNWORKER_H
#define DNSWORKER_H

#include <future>
#include <mutex>
#include <string>
#include <condition_variable>
#include <vector>
#include <memory>

#include <pcapwrapper/network/packages/udppackage.h>

class DNSWorker {
public:
    DNSWorker(std::unique_ptr<PCAP::UDPPackage> package);
    void new_session(std::unique_ptr<PCAP::UDPPackage> package);

    void finish();
    PCAP::IpAddress get_src_ip() const;
private:
    std::vector<std::string> m_tmp_websites;
    PCAP::IpAddress m_src_ip;

    std::condition_variable m_worker_cond;
    std::mutex m_worker_mutex;
    bool m_worker_finished;
    std::future<void> m_worker;

    std::string m_file_name;

    void worker();

};

#endif
