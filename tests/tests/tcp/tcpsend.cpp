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
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>

#include "../common.h"
#include "../interfacetest.h"

class ListenerSendTCP : public PCAP::PackageListener<PCAP::TCPPackage>,
                    public FinishTest
{
public:
    ListenerSendTCP(PCAP::TCPPackage package)
        : m_package{package}
    {}

    void receivedPackage(PCAP::TCPPackage package) override {
        EXPECT_EQ(m_package.getLength(), package.getLength());
        EXPECT_EQ(package, m_package);
        m_done = true;
    }
private:
    PCAP::TCPPackage m_package;
};

class TestSendTCP : public ::testing::Test
{
protected:
    virtual void SetUp() {
        unlink("tmp-file.pcap");
    }

    virtual void TearDown() {
        unlink("tmp-file.pcap");
    }
};

TEST_F(TestSendTCP, TestSendOnePackage) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_tcp(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option{PCAP::MacAddress("80:80:80:AA:AA:AA")}},
        {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress{"80:80:80:AA:BB:CC"}}},
        {Keys::Key_Ip_Src, Option{PCAP::IpAddress{"128.23.21.55"}}},
        {Keys::Key_Ip_Dst, Option{PCAP::IpAddress{"123.22.33.22"}}},
        {Keys::Key_Ip_TTL, Option{(unsigned char)0x60}},
        {Keys::Key_Ip_Flags, Option{(unsigned char)0x02}},
        {Keys::Key_Ip_Id, Option{(unsigned short)0x0102}},
        {Keys::Key_Ip_Length, Option{(unsigned short)0x3c}},
        {Keys::Key_Src_Port, Option{(unsigned short)0x5023}},
        {Keys::Key_Dst_Port, Option{(unsigned short)0x4241}},
        {Keys::Key_Tcp_SeqNr, Option{(unsigned int)0x12324}},
        {Keys::Key_Tcp_AckNr, Option{(unsigned int)0x332123}},
        {Keys::Key_Tcp_Flags, Option{(unsigned char)0x04}}});
    package.recalculateChecksums();
    send_package(package);

    std::string filename = std::string("tmp-file.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerSendTCP>(package);
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}