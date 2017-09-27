#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

class ListenerReceiveUDP : public PCAP::PackageListener<PCAP::UDPPackage>,
                           public FinishTest {
  public:
    // expected values are from file
    void receive_package(PCAP::UDPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("00:26:16:00:00:d2"), package.get_dst_mac());
        EXPECT_EQ(PCAP::MacAddress("00:0C:29:50:A9:FC"), package.get_src_mac());
        EXPECT_EQ(0x0800, package.get_ether_type());
        EXPECT_EQ(0x45, package.get_vhl());
        EXPECT_EQ(0x00, package.get_tos());
        EXPECT_EQ(0x29, package.get_total_length());
        EXPECT_EQ(0x0000, package.get_id());
        EXPECT_EQ(0x02, package.get_ip_flags());
        EXPECT_EQ(0x0, package.get_fragment_offset());
        EXPECT_EQ(0x40, package.get_ttl());
        EXPECT_EQ(0x11, package.get_protocol());
        EXPECT_EQ(PCAP::IpAddress("192.168.0.101"), package.get_src_ip());
        EXPECT_EQ(PCAP::IpAddress("192.168.0.10"), package.get_dst_ip());
        EXPECT_EQ(0xc2f1, package.get_src_port());
        EXPECT_EQ(0x13e6, package.get_dst_port());
        EXPECT_EQ(0x15, package.get_udp_length());
        m_done = true;
    }
};

TEST(TestReceiveUDP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/udp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveUDP>();
    controller->add_listener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}