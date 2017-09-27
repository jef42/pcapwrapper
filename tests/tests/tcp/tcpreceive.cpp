#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

class ListenerReceiveTCP : public PCAP::PackageListener<PCAP::TCPPackage>,
                           public FinishTest {
  public:
    // expected values are from file
    void receive_package(PCAP::TCPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("9C:97:26:6e:81:90"), package.get_src_mac());
        EXPECT_EQ(PCAP::MacAddress("80:A5:89:8C:6F:43"), package.get_dst_mac());
        EXPECT_EQ(0x0800, package.get_ether_type());
        EXPECT_EQ(0x45, package.get_vhl());
        EXPECT_EQ(0x00, package.get_tos());
        EXPECT_EQ(0x3C, package.get_total_length());
        EXPECT_EQ(0x5e86, package.get_id());
        EXPECT_EQ(0x02, package.get_ip_flags());
        EXPECT_EQ(0x0, package.get_fragment_offset());
        EXPECT_EQ(0x70, package.get_ttl());
        EXPECT_EQ(0x06, package.get_protocol());
        EXPECT_EQ(PCAP::IpAddress("40.77.226.250"), package.get_src_ip());
        EXPECT_EQ(PCAP::IpAddress("192.168.1.159"), package.get_dst_ip());
        EXPECT_EQ(0x01bb, package.get_src_port());
        EXPECT_EQ(0xd880, package.get_dst_port());
        EXPECT_EQ(0xa3b019e3, package.get_seq_nr());
        EXPECT_EQ(0x82823c71, package.get_ack_nr());
        EXPECT_EQ(0x0a, package.get_data_offset());
        EXPECT_EQ(0x12, package.get_tcp_flags());
        EXPECT_EQ(0x2000, package.get_window_size());
        EXPECT_EQ(0x0000, package.get_urgent_ptr());
        m_done = true;
    }
};

TEST(TestReceiveTCP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveTCP>();
    controller->add_listener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}