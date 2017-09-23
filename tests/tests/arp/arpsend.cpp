#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

class ListenerSendARP : public PCAP::PackageListener<PCAP::ARPPackage>,
                        public FinishTest {
  public:
    ListenerSendARP(PCAP::ARPPackage package) : m_package{package} {}

    void receivedPackage(PCAP::ARPPackage package) override {
        EXPECT_EQ(m_package.getLength(), package.getLength());
        EXPECT_EQ(package, m_package);
        EXPECT_FALSE(package != m_package);
        m_done = true;
    }

  private:
    PCAP::ARPPackage m_package;
};

class TestSendARP : public ::testing::Test {
  protected:
    virtual void SetUp() { unlink("tmp-file.pcap"); }
    virtual void TearDown() { unlink("tmp-file.pcap"); }
};

TEST_F(TestSendARP, TestSendOnePackage) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_arp(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option{PCAP::MacAddress("80:80:80:AA:AA:AA")}},
        {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress("90:11:22:33:44:55")}},
        {Keys::Key_Arp_Mac_Src, Option{PCAP::MacAddress("22:22:11:53:23:56")}},
        {Keys::Key_Arp_Mac_Dst, Option{PCAP::MacAddress("21:33:45:12:32:45")}},
        {Keys::Key_Arp_Opcode, Option{(unsigned char)0x1}},
        {Keys::Key_Ip_Src, Option{PCAP::IpAddress("192.167.53.23")}},
        {Keys::Key_Ip_Dst, Option{PCAP::IpAddress("129.23.55.44")}}});
    send_package(package);

    std::string filename = std::string("tmp-file.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerSendARP>(package);
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}