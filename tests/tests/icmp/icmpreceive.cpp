#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>

#include "../common.h"

class ListenerReceiveICMP : public PCAP::PackageListener<PCAP::ICMPPackage>,
                    public FinishTest
{
public:
    //expected values are from file
    void receivedPackage(PCAP::ICMPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("9C:97:26:6e:81:90"), package.getDstMac());
        EXPECT_EQ(PCAP::MacAddress("80:A5:89:8C:6F:43"), package.getSrcMac());
        EXPECT_EQ(0x0800, package.getEtherType());
        EXPECT_EQ(0x45, package.getVHL());
        EXPECT_EQ(0x00, package.getTOS());
        EXPECT_EQ(0x54, package.getTotalLength());
        EXPECT_EQ(0x0b89, package.getID());
        EXPECT_EQ(0x02, package.getIpFlags());
        EXPECT_EQ(0x0, package.getFragmentOffset());
        EXPECT_EQ(0x40, package.getTTL());
        EXPECT_EQ(0x01, package.getProtocol());
        EXPECT_EQ(PCAP::IpAddress("8.8.8.8"), package.getDstIp());
        EXPECT_EQ(PCAP::IpAddress("192.168.1.159"), package.getSrcIp());
        EXPECT_EQ(0x08, package.getType());
        EXPECT_EQ(0x00, package.getCode());
        m_done = true;
    }
};

TEST(TestReceiveICMP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/icmp1package.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveICMP>();
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}