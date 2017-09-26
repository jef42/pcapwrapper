#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/listeners/maclistener.h>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/network/addresses/ipaddress.h>
#include <pcapwrapper/network/addresses/macaddress.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

class MacListenerHelper : public ::testing::Test {
  protected:
    virtual void SetUp() { unlink("tmp-file.pcap"); }

    virtual void TearDown() { unlink("tmp-file.pcap"); }
};

TEST_F(MacListenerHelper, MacListener) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_arp(
        std::map<Keys, Option>{std::map<Keys, Option>{
            {Keys::Key_Eth_Mac_Src,
             Option{PCAP::MacAddress{"AA:BB:CC:DD:EE:FF"}}},
            {Keys::Key_Arp_Mac_Src,
             Option{PCAP::MacAddress{"AA:BB:CC:DD:EE:FF"}}},
            {Keys::Key_Ip_Src, Option{PCAP::IpAddress("192.168.1.2")}},
            {Keys::Key_Arp_Opcode, Option{(unsigned short)0x2}}}});
    send_package(package); // writes to a file

    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(
        "tmp-file.pcap");
    auto mac_listener = std::make_shared<PCAP::PCAPHelper::MacListener>(
        PCAP::IpAddress("192.168.1.2"));
    controller->addListener(mac_listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(1200));
    EXPECT_EQ(PCAP::MacAddress("AA:BB:CC:DD:EE:FF"), mac_listener->getMac());
}
