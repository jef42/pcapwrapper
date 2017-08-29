#ifndef DNSSESSIONCONTROLLER_H
#define DNSSESSIONCONTROLLER_H

#include <vector>

#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>

class DNSSessionController : public PCAP::PackageListener<PCAP::UDPPackage> {
public:
    DNSSessionController(const PCAP::MacAddress& local_mac, const PCAP::IpAddress& local_ip, const PCAP::IpAddress &router_ip,
                         const PCAP::MacAddress& router_mac, const std::string& interface_name, bool force_all);
private:
    struct PatternMatching {
        PatternMatching(const std::string& website, std::string& ip)
            : m_website{website}
            , m_ip{ip}{}
        std::string m_website;
        std::string m_ip;
    };

    void receivedPackage(PCAP::UDPPackage package) override;
    void send_reply(PCAP::UDPPackage package, const std::string &ip);
    void forward_question(PCAP::UDPPackage package);
    void read_websites();
    std::string is_block_website(const std::string& data);

    const PCAP::MacAddress& m_local_mac;
    const PCAP::IpAddress& m_local_ip;
    const std::string& m_interface_name;

    const PCAP::IpAddress& m_router_ip;
    const PCAP::MacAddress& m_router_mac;

    const bool m_force_all;

    std::vector<PatternMatching> m_block_websites;
};

#endif // DNSSESSIONCONTROLLER_H
