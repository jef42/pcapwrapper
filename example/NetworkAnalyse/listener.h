#ifndef LISTENER_H
#define LISTENER_H

#include <mutex>
#include <pcapwrapper/network/addresses/ipaddress.h>

class Listener {
public:
    Listener(const PCAP::IpAddress& ip);
    void inc_count();
    unsigned long get_count();
private:
    std::mutex m_lock;
    unsigned long m_count;
protected:
    PCAP::IpAddress m_ip;
};

#endif
