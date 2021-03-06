#include <gtest/gtest.h>
#include <vector>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

TEST(IpOperation, get_ips) {
    auto address = PCAP::IpAddress{"192.168.1.2"};
    auto netmask = PCAP::IpAddress{"255.255.255.0"};
    auto ips = PCAP::PCAPHelper::get_ips(address, netmask);
    EXPECT_EQ(256, ips.size());
}