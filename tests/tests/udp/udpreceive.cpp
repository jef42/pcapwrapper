#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>

#include "../common.h"

class ListenerReceiveUDP : public PCAP::PackageListener<PCAP::UDPPackage>,
                    public FinishTest
{
public:
    //expected values are from file
    void receivedPackage(PCAP::UDPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("00:26:16:00:00:d2"), package.getDstMac());
        EXPECT_EQ(PCAP::MacAddress("00:0C:29:50:A9:FC"), package.getSrcMac());
        EXPECT_EQ(0x0800, package.getEtherType());
        EXPECT_EQ(0x45, package.getVHL());
        EXPECT_EQ(0x00, package.getTOS());
        EXPECT_EQ(0x29, package.getTotalLength());
        EXPECT_EQ(0x0000, package.getID());
        EXPECT_EQ(0x02, package.getIpFlags());
        EXPECT_EQ(0x0, package.getFragmentOffset());
        EXPECT_EQ(0x40, package.getTTL());
        EXPECT_EQ(0x11, package.getProtocol());
        EXPECT_EQ(PCAP::IpAddress("192.168.0.101"), package.getSrcIp());
        EXPECT_EQ(PCAP::IpAddress("192.168.0.10"), package.getDstIp());
        EXPECT_EQ(0xc2f1, package.getSrcPort());
        EXPECT_EQ(0x13e6, package.getDstPort());
        EXPECT_EQ(0x15, package.getUDPLength());
        m_done = true;
    }
};

TEST(TestReceiveUDP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/udp1package.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveUDP>();
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}