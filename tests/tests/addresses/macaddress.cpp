#include <gtest/gtest.h>

#include <pcapwrapper/network/addresses/macaddress.h>

TEST(MacAddress, Equal) {
    PCAP::MacAddress a(std::string("FF:AA:00:FF:11:AA"));
    PCAP::MacAddress b("FF:AA:00:FF:11:AA");
    EXPECT_EQ(a,b);
    EXPECT_EQ(a.to_string(), b.to_string());
    EXPECT_FALSE(a != b);
    EXPECT_TRUE(a == b);
    EXPECT_TRUE(memcmp(a.data(), b.data(), 6) == 0);
}

TEST(MacAddress, NotEqual) {
    PCAP::MacAddress a(std::string("FF:AA:00:FF:AA:11"));
    PCAP::MacAddress b(std::string("FF:AA:00:FF:AA:12"));
    EXPECT_NE(a,b);
    EXPECT_NE(a.to_string(), b.to_string());
    EXPECT_FALSE(a == b);
    EXPECT_FALSE(memcmp(a.data(), b.data(), 6) == 0);
}

TEST(MacAddress, Default) {
    PCAP::MacAddress a;
    EXPECT_EQ(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"), a);
}

TEST(MacAddress, Invalid) {
    EXPECT_THROW(PCAP::MacAddress("AA"), std::runtime_error);
    //EXPECT_THROW(PCAP::MacAddress("AA.AA.AA.AA.AA.AA.AA.AA"), std::runtime_error);
    //EXPECT_THROW(PCAP::MacAddress("AA:A:AA:AA:AA:AA:AA"), std::runtime_error);
}