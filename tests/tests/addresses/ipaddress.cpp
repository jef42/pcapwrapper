#include <gtest/gtest.h>
#include <stdexcept>
#include <sstream>

#include <pcapwrapper/network/addresses/ipaddress.h>

TEST(IpAddress, Equal) {
    PCAP::IpAddress a(std::string("192.168.1.1"));
    PCAP::IpAddress b("192.168.1.1");
    EXPECT_EQ(a,b);
    EXPECT_EQ(a.to_string(), b.to_string());
    EXPECT_EQ(a.to_long(), b.to_long());
    EXPECT_EQ(a, a & b);
    EXPECT_TRUE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, NotEqual) {
    PCAP::IpAddress a("192.168.2.1");
    PCAP::IpAddress b(111234677);
    EXPECT_NE(a,b);
    EXPECT_NE(a.to_string(), b.to_string());
    EXPECT_NE(a.to_long(), b.to_long());
    EXPECT_NE(a, a & b);
    EXPECT_FALSE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, Default) {
    PCAP::IpAddress a;
    EXPECT_EQ(PCAP::IpAddress("255.255.255.255"), a);
}

TEST(IpAddress, Compare) {
    PCAP::IpAddress a("192.168.2.1");
    PCAP::IpAddress b("192.168.3.1");
    EXPECT_TRUE(a != b);
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(a > b);
}

TEST(IpAddress, Invalid) {
    EXPECT_THROW(PCAP::IpAddress("0"), std::runtime_error);
    EXPECT_THROW(PCAP::IpAddress("0:0:0:0"), std::runtime_error);
}

TEST(IpAddress, Stream) {
    PCAP::IpAddress ip("1.2.3.4");
    std::stringstream stream;
    stream << ip;
    EXPECT_EQ(ip.to_string(), stream.str());
}