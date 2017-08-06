#ifndef LISTENER_H
#define LISTENER_H

#include <mutex>
#include <unordered_map>
#include <atomic>
#include <vector>
#include <pcapwrapper/network/addresses/ipaddress.h>

namespace std {
  template <>
  struct hash<PCAP::IpAddress>
  {
    std::size_t operator()(const PCAP::IpAddress& k) const
    {
        return hash<long>()(k.to_long());
    }
  };
}

class Listener {
public:
    Listener(const PCAP::IpAddress& ip);
    void inc_count(PCAP::IpAddress ip);
    std::vector<std::pair<PCAP::IpAddress, unsigned int>> get_count();
private:
    std::mutex m_lock;
protected:
    PCAP::IpAddress m_netmask;
    std::unordered_map<PCAP::IpAddress, std::atomic<unsigned int>> m_counts;
};

#endif
