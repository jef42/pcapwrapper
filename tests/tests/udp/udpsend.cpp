#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <unistd.h>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/processors/processorsave.h>

#include "../common.h"
#include "../interfacetest.h"

class ListenerSendUDP : public PCAP::PackageListener<PCAP::UDPPackage>,
                        public FinishTest {
  public:
    ListenerSendUDP(PCAP::UDPPackage package) : m_package{package} {}

    void receive_package(PCAP::UDPPackage package) override {
        EXPECT_EQ(m_package.get_length(), package.get_length());
        EXPECT_EQ(package, m_package);
        EXPECT_FALSE(package != m_package);
        m_done = true;
    }

  private:
    PCAP::UDPPackage m_package;
};

class TestSendUDP : public ::testing::Test {
  protected:
    virtual void SetUp() { unlink("tmp-file.pcap"); }

    virtual void TearDown() { unlink("tmp-file.pcap"); }
};

TEST_F(TestSendUDP, TestSendOnePackage) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option{PCAP::MacAddress("80:80:80:AA:AA:AA")}},
        {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress{"80:80:80:AA:BB:CC"}}},
        {Keys::Key_Ip_Src, Option{PCAP::IpAddress{"128.23.21.55"}}},
        {Keys::Key_Ip_Dst, Option{PCAP::IpAddress{"123.22.33.22"}}},
        {Keys::Key_Ip_TTL, Option{(PCAP::uchar)0x60}},
        {Keys::Key_Ip_Flags, Option{(PCAP::uchar)0x02}},
        {Keys::Key_Ip_Id, Option{(PCAP::ushort)0x0102}},
        {Keys::Key_Ip_Length, Option{(PCAP::ushort)0x29}},
        {Keys::Key_Src_Port, Option{(PCAP::ushort)0x5023}},
        {Keys::Key_Dst_Port, Option{(PCAP::ushort)0x4241}},
        {Keys::Key_Udp_Length, Option{(PCAP::ushort)0x15}}});
    package.recalculate_checksums();
    send_package(package);

    std::string filename = std::string("tmp-file.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerSendUDP>(package);
    controller->add_listener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}

TEST_F(TestSendUDP, TestAppendData) {
    using namespace PCAP::PCAPBuilder;
    constexpr uint data_size = 6;
    auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{});
    PCAP::uchar data[data_size] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
    PCAP::uchar data_result[data_size * 2] = {1, 2, 3, 4, 5, 6,
                                              1, 2, 3, 4, 5, 6};
    package.append_data(data, data_size);
    EXPECT_EQ(package.get_data_length(), data_size);
    EXPECT_TRUE(memcmp(package.get_data(), data, package.get_data_length()) ==
                0);
    package.append_data(data, data_size);
    EXPECT_EQ(package.get_data_length(), data_size * 2);
    EXPECT_TRUE(memcmp(package.get_data(), data_result,
                       package.get_data_length()) == 0);
}