#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/processors/processorempty.h>
#include <pcapwrapper/listeners/packagelistener.h>

#include "../common.h"
#include "../interfacetest.h"

TEST(ProcessorEmpty, ProcessorEmptyNoReceive) {
    std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<PCAP::Controller<PCAP::InterfaceFile, PCAP::ProcessorEmpty>>(filename);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    controller->stop();
}