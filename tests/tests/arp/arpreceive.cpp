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
    void receivedPackage(PCAP::ARPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("FF:FF:FF:FF:FF:FF"), package.getDstMac());
        EXPECT_EQ(PCAP::MacAddress("00:07:0d:af:f4:54"), package.getSrcMac());
        EXPECT_EQ(0x0806, package.getEtherType());
        EXPECT_EQ(PCAP::IpAddress("24.166.172.1"), package.getSrcIp());
        EXPECT_EQ(PCAP::IpAddress("24.166.173.161"), package.getDstIp());
        EXPECT_EQ(PCAP::MacAddress("00:07:0d:af:f4:54"),
                  package.getSrcArpMac());
        EXPECT_EQ(PCAP::MacAddress("00:00:00:00:00:00"),
                  package.getDstArpMac());
        EXPECT_EQ(0x1, package.getHardwareType());
        EXPECT_EQ(0x6, package.getHardwareLength());
        EXPECT_EQ(0x800, package.getProtocol());
        EXPECT_EQ(0x4, package.getProtocolLength());
        EXPECT_EQ(0x1, package.getOpcode());
        m_done = true;
    }
};

TEST(TestReceiveARP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/arp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveARP>();
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}