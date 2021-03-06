#include <chrono>
#include <gtest/gtest.h>
#include <memory>

#include "../common.h"
#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/sessions/session.h>
#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/network/sessions/sessioncontroller.h>
#include <pcapwrapper/processors/processor.h>

class SessionControllerTest : public PCAP::SessionController {
  public:
    virtual void new_session(const PCAP::Session &, PCAP::TCPPackage) {
        new_tcp_session = true;
    }
    virtual void append_session(const PCAP::Session &, PCAP::TCPPackage) {
        app_tcp_session = true;
    }
    virtual void finished_session(const PCAP::Session &) {
        fin_tcp_session = true;
    }
    virtual void new_session(const PCAP::Session &, PCAP::UDPPackage) {
        new_udp_session = true;
    }
    virtual void append_session(const PCAP::Session &, PCAP::UDPPackage) {
        app_udp_session = true;
    }

    bool new_tcp_session = {false};
    bool app_tcp_session = {false};
    bool fin_tcp_session = {false};
    bool new_udp_session = {false};
    bool app_udp_session = {false};
};

TEST(TestSendSession, new_session) {
    const std::string filename = "../pcapfiles/session.pcap";
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto session_controller = std::make_shared<SessionControllerTest>();
    controller->add_session_controller(session_controller);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_TRUE(session_controller->new_tcp_session);
    EXPECT_TRUE(session_controller->app_tcp_session);
    EXPECT_TRUE(session_controller->fin_tcp_session);
    EXPECT_TRUE(session_controller->new_udp_session);
    EXPECT_TRUE(session_controller->app_udp_session);
}

TEST(TestSendSession, NoSession) {
    const std::string filename = "../pcapfiles/session.pcap";
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto session_controller = std::make_shared<SessionControllerTest>();
    controller->add_session_controller(session_controller);
    controller->remove_session_controller(session_controller);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_FALSE(session_controller->new_tcp_session);
    EXPECT_FALSE(session_controller->app_tcp_session);
    EXPECT_FALSE(session_controller->fin_tcp_session);
    EXPECT_FALSE(session_controller->new_udp_session);
    EXPECT_FALSE(session_controller->app_udp_session);
}