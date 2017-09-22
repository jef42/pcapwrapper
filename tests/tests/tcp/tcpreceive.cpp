#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>

#include "../common.h"

class ListenerReceiveTCP : public PCAP::PackageListener<PCAP::TCPPackage>,
                    public FinishTest
{
public:
    //expected values are from file
    void receivedPackage(PCAP::TCPPackage package) override {
        EXPECT_EQ(PCAP::MacAddress("9C:97:26:6e:81:90"), package.getSrcMac());
        EXPECT_EQ(PCAP::MacAddress("80:A5:89:8C:6F:43"), package.getDstMac());
        EXPECT_EQ(0x0800, package.getEtherType());
        EXPECT_EQ(0x45, package.getVHL());
        EXPECT_EQ(0x00, package.getTOS());
        EXPECT_EQ(0x3C, package.getTotalLength());
        EXPECT_EQ(0x5e86, package.getID());
        EXPECT_EQ(0x02, package.getIpFlags());
        EXPECT_EQ(0x0, package.getFragmentOffset());
        EXPECT_EQ(0x70, package.getTTL());
        EXPECT_EQ(0x06, package.getProtocol());
        EXPECT_EQ(PCAP::IpAddress("40.77.226.250"), package.getSrcIp());
        EXPECT_EQ(PCAP::IpAddress("192.168.1.159"), package.getDstIp());
        EXPECT_EQ(0x01bb, package.getSrcPort());
        EXPECT_EQ(0xd880, package.getDstPort());
        EXPECT_EQ(0xa3b019e3, package.getSeqNr());
        EXPECT_EQ(0x82823c71, package.getAckNr());
        EXPECT_EQ(0x0a, package.getDataOffset());
        EXPECT_EQ(0x12, package.getTcpFlags());
        EXPECT_EQ(0x2000, package.getWindowSize());
        EXPECT_EQ(0x0000, package.getUrgentPtr());
        m_done = true;
    }
};

TEST(TestReceiveTCP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveTCP>();
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}