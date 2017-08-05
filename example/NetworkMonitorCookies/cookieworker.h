#ifndef HTTPWORKER_H
#define HTTPWORKER_H

#include <future>
#include <mutex>
#include <string>
#include <condition_variable>
#include <vector>
#include <memory>

#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

class CookieWorker {
public:
    CookieWorker(std::unique_ptr<PCAP::TCPPackage> package);
    void new_package(std::unique_ptr<PCAP::TCPPackage> package);

    void finish();
    PCAP::IpAddress get_src_ip() const;
private:
    std::vector<std::string> m_payloads;
    std::vector<std::string> m_websites;
    PCAP::IpAddress m_src_ip;

    std::condition_variable m_worker_cond;
    std::mutex m_worker_mutex;
    bool m_worker_finished;
    std::future<void> m_worker;

    std::string m_file_name;

    void worker();
};

#endif
