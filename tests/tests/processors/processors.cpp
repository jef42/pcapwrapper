#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/processors/processorempty.h>

#include "../common.h"
#include "../interfacetest.h"

class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>,
                    public FinishTest {
  public:
    void receivedPackage(PCAP::TCPPackage) override { m_done = true; }
};

class UDPListener : public PCAP::PackageListener<PCAP::UDPPackage>,
                    public FinishTest {
  public:
    void receivedPackage(PCAP::UDPPackage) override { m_done = true; }
};

class ICMPListener : public PCAP::PackageListener<PCAP::ICMPPackage>,
                     public FinishTest {
  public:
    void receivedPackage(PCAP::ICMPPackage) override { m_done = true; }
};

class ARPListener : public PCAP::PackageListener<PCAP::ARPPackage>,
                    public FinishTest {
  public:
    void receivedPackage(PCAP::ARPPackage) override { m_done = true; }
};

TEST(ProcessorEmpty, ProcessorEmptyNoReceive) {
    std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::ProcessorEmpty>>(filename);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    controller->stop();
}

TEST(Processors, removeListener) {
    const std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto tcp_listener = std::make_shared<TCPListener>();
    auto udp_listener = std::make_shared<UDPListener>();
    auto icmp_listener = std::make_shared<ICMPListener>();
    auto arp_listener = std::make_shared<ARPListener>();

    controller->addListener(tcp_listener);
    controller->addListener(udp_listener);
    controller->addListener(icmp_listener);
    controller->addListener(arp_listener);

    controller->removeListener(tcp_listener);
    controller->removeListener(udp_listener);
    controller->removeListener(icmp_listener);
    controller->removeListener(arp_listener);

    controller->start();
    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_FALSE(tcp_listener->is_done());
    EXPECT_FALSE(udp_listener->is_done());
    EXPECT_FALSE(icmp_listener->is_done());
    EXPECT_FALSE(arp_listener->is_done());
}

TEST(Processors, clearListeners) {
    const std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto tcp_listener = std::make_shared<TCPListener>();
    auto udp_listener = std::make_shared<UDPListener>();
    auto icmp_listener = std::make_shared<ICMPListener>();
    auto arp_listener = std::make_shared<ARPListener>();

    controller->clearAllListeners();
    controller->start();
    
    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_FALSE(tcp_listener->is_done());
    EXPECT_FALSE(udp_listener->is_done());
    EXPECT_FALSE(icmp_listener->is_done());
    EXPECT_FALSE(arp_listener->is_done());
}