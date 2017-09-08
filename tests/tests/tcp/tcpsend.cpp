#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <unistd.h>

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
        EXPECT_TRUE(memcmp(m_package.getPackage(), m_package.getPackage(), m_package.getLength()));
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

template <typename T>
void send_package(T package) {
    auto processor = std::make_shared<PCAP::ProcessorSave>();
    auto interface = std::make_shared<InterfaceTest>(processor);
    interface->write(package.getPackage(), package.getLength());
    processor->save("tmp-file.pcap");
}

TEST_F(TestSendTCP, TestSendOnePackage) {
    using namespace PCAP::PCAPBuilder;
    auto package = PCAP::PCAPBuilder::make_tcp(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option{PCAP::MacAddress("80:80:80:AA:AA:AA")}},
    });
    package.recalculateChecksums();
    send_package(package);

    std::string filename = std::string("tmp-file.pcap");
    auto controller = PCAP::Controller<PCAP::InterfaceFile, PCAP::Processor>::getController(filename);
    auto listener = std::make_shared<ListenerSendTCP>(package);
    controller->addListener(listener);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    EXPECT_EQ(true, listener->is_done());
    controller->stop();
}