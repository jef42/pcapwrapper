#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/processors/processorsave.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>

#include "../common.h"
#include "../interfacetest.h"

class ListenerSendUDP : public PCAP::PackageListener<PCAP::UDPPackage>,
                    public FinishTest
{
public:
    ListenerSendUDP(PCAP::UDPPackage package)
        : m_package{package}
    {}

    void receivedPackage(PCAP::UDPPackage package) override {
        EXPECT_EQ(m_package.getLength(), package.getLength());
        EXPECT_EQ(package, m_package);
        EXPECT_FALSE(package != m_package);
        m_done = true;
    }
private:
    PCAP::UDPPackage m_package;
};

class TestSendUDP : public ::testing::Test
{
protected:
    virtual void SetUp() {
        unlink("tmp-file.pcap");
    }

    virtual void TearDown() {
        unlink("tmp-file.pcap");
    }
};

TEST_F(TestSendUDP, TestSendOnePackage) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option{PCAP::MacAddress("80:80:80:AA:AA:AA")}},
        {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress{"80:80:80:AA:BB:CC"}}},
        {Keys::Key_Ip_Src, Option{PCAP::IpAddress{"128.23.21.55"}}},
        {Keys::Key_Ip_Dst, Option{PCAP::IpAddress{"123.22.33.22"}}},
        {Keys::Key_Ip_TTL, Option{(unsigned char)0x60}},
        {Keys::Key_Ip_Flags, Option{(unsigned char)0x02}},
        {Keys::Key_Ip_Id, Option{(unsigned short)0x0102}},
        {Keys::Key_Ip_Length, Option{(unsigned short)0x29}},
        {Keys::Key_Src_Port, Option{(unsigned short)0x5023}},
        {Keys::Key_Dst_Port, Option{(unsigned short)0x4241}},
        {Keys::Key_Udp_Length, Option{(unsigned short)0x15}}});
    package.recalculateChecksums();
    send_package(package);

    std::string filename = std::string("tmp-file.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerSendUDP>(package);
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}

TEST_F(TestSendUDP, TestAppendData) {
    using namespace PCAP::PCAPBuilder;
    constexpr unsigned int data_size = 6;
    auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{});
    unsigned char data[data_size] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
    unsigned char data_result[data_size * 2] = {1,2,3,4,5,6,1,2,3,4,5,6};
    package.appendData(data, data_size);
    EXPECT_EQ(package.getDataLength(), data_size);
    EXPECT_TRUE(memcmp(package.getData(), data, package.getDataLength()) == 0);
    package.appendData(data, data_size);
    EXPECT_EQ(package.getDataLength(), data_size * 2);
    EXPECT_TRUE(memcmp(package.getData(), data_result, package.getDataLength()) == 0);
}