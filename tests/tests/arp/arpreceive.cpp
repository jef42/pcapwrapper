#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/network/packages/arppackage.h>
#include <pcapwrapper/network/addresses/macaddress.h>

#include "../common.h"

class ListenerReceiveARP : public PCAP::PackageListener<PCAP::ARPPackage>,
                    public FinishTest
{
public:
    //expected values are from file
    void receivedPackage(PCAP::ARPPackage package) override {
        
        m_done = true;
    }
};

TEST(TestReceiveARP, TestReceiveOnePackage) {
    std::string filename = std::string("../pcapfiles/arp1package.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>>(filename);
    auto listener = std::make_shared<ListenerReceiveARP>();
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}