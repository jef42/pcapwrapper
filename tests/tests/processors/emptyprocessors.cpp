#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/interfaces/interfacefile.h>
#include <pcapwrapper/listeners/packagelistener.h>
#include <pcapwrapper/processors/processor.h>
#include <pcapwrapper/processors/processorempty.h>

#include "../common.h"
#include "../interfacetest.h"

TEST(ProcessorEmpty, ProcessorEmptyNoReceive) {
    std::string filename = std::string("../pcapfiles/tcp1package.pcap");
    auto controller = std::make_shared<
        PCAP::Controller<PCAP::InterfaceFile, PCAP::ProcessorEmpty>>(filename);
    controller->start();

    wait_test_finished(std::chrono::milliseconds(200));
    controller->stop();
}