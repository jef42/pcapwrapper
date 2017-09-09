#include <gtest/gtest.h>
#include <chrono>
#include <thread>

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
        m_done = true;
    }
};

TEST(TestReceiveTCP, TestOnePackage) {
    // std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    // auto controller = PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>::getController(filename);
    // auto listener = std::make_shared<ListenerReceiveTCP>();
    // controller->addListener(listener);
    // controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    //ASSERT_EQ(true, listener->is_done());
    //controller->stop();
}