#ifndef HTTPWORKER_H
#define HTTPWORKER_H

#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/packages/tcppackage.h>

class CookieWorker {
  public:
    CookieWorker(PCAP::TCPPackage package);
    void new_package(PCAP::TCPPackage package);

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
