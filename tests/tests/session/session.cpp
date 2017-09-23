#include <gtest/gtest.h>
#include <tuple>

#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/packages/ippackage.h>


TEST(Session, CreateSession) {
    const PCAP::IpAddress addr_src("1.2.3.4");
    const PCAP::IpAddress addr_dst("5.6.7.8");
    const unsigned short port_src = 12345;
    const unsigned short port_dst = 4567;
    PCAP::Session session1{addr_src, addr_dst, port_src, port_dst};
    auto ips = session1.get_ips();
    EXPECT_TRUE(addr_src == std::get<0>(ips));
    EXPECT_TRUE(addr_dst == std::get<1>(ips));
    auto ports = session1.get_ports();
    EXPECT_TRUE(port_src == std::get<0>(ports));
    EXPECT_TRUE(port_src == std::get<0>(ports));
}

TEST(Session, CreateSessions) {
    const PCAP::IpAddress addr_src("1.2.3.4");
    const PCAP::IpAddress addr_dst("5.6.7.8");
    const unsigned short port_src = 12345;
    const unsigned short port_dst = 4567;
    PCAP::Session session1{addr_src, addr_dst, port_src, port_dst};
    PCAP::Session session2{addr_src, addr_dst, port_src, port_dst};
    EXPECT_TRUE(session1 == session2);
    EXPECT_FALSE(session1 != session2);

}