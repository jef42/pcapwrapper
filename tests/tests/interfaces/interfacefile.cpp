#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <string>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/common.h>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/processors/processor.h>

#include "../common.h"

TEST(FileInterface, FileNotFound) {
    const std::string filename = "../pcapfiles/no-file.pcap";
    bool it_throws = false;
    try {
        auto controller = std::make_shared<
            PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    } catch (std::invalid_argument &) {
        it_throws = true;
    }
    EXPECT_TRUE(it_throws);
}

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>,
                    public FinishTest {
  public:
    void receive_package(PCAP::TCPPackage) override { m_done = true; }
};

class UDPListener : public PCAP::PackageListener<PCAP::UDPPackage>,
                    public FinishTest {
  public:
    void receive_package(PCAP::UDPPackage) override { m_done = true; }
};

TEST(FileInterface, Filter) {
    const std::string filename = "../pcapfiles/session.pcap";
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    EXPECT_TRUE(controller->set_filter("tcp"));
    auto tcp_listener = std::make_shared<TCPListener>();
    auto udp_listener = std::make_shared<UDPListener>();

    controller->add_listener(tcp_listener);
    controller->add_listener(udp_listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_TRUE(tcp_listener->is_done());
    EXPECT_FALSE(udp_listener->is_done());
}

TEST(FileInterface, Write) {
    const std::string filename = "../pcapfiles/session.pcap";
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_udp(std::map<Keys, Option>{});
    EXPECT_EQ(-1,
              controller->write(package.get_package(), package.get_length()));
}