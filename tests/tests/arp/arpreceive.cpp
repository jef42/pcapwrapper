#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

class ListenerReceiveARP : public PCAP::PackageListener<PCAP::ARPPackage>,
                           public FinishTest {
  public:
    // expected values are from file
    void receive_package(PCAP::ARPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"), package.get_dst_mac());
        EXPECT_EQ(PCAP::MacAddress("00:07:0d:af:f4:54"), package.get_src_mac());
        EXPECT_EQ(0x0806, package.get_ether_type());
        EXPECT_EQ(PCAP::IpAddress("24.166.172.1"), package.get_src_ip());
        EXPECT_EQ(PCAP::IpAddress("24.166.173.161"), package.get_dst_ip());
        EXPECT_EQ(PCAP::MacAddress("00:07:0d:af:f4:54"),
                  package.get_src_arp_mac());
        EXPECT_EQ(PCAP::MacAddress("00:00:00:00:00:00"),
                  package.get_dst_arp_mac());
        EXPECT_EQ(0x1, package.get_hardware_type());
        EXPECT_EQ(0x6, package.get_hardware_length());
        EXPECT_EQ(0x800, package.get_protocol());
        EXPECT_EQ(0x4, package.get_protocol_length());
        EXPECT_EQ(0x1, package.get_opcode());
        m_done = true;
    }
};

TEST(TestReceiveARP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/arp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveARP>();
    controller->add_listener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}