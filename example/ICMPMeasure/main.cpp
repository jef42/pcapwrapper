#include <iostream>
#include <string>
#include <memory>

#include <pcapwrapper/controller.hpp>
#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/performancemeasurement.h>
#include <pcapwrapper/processors/processorempty.h>
#include <pcapwrapper/interfaces/interface.h>
#include <pcapwrapper/network/builders/builder.h>
#include <pcapwrapper/network/builders/keys.h>

static const int N = 50000;

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Wrong nr of parameters\n";
        std::cout << "1. Interface name";
    }

    const auto local_ip = PCAP::PCAPHelper::getIp(argv[1]);
    const auto local_mac = PCAP::PCAPHelper::getMac(argv[1]);

    auto controller = std::make_shared<PCAP::Controller<PCAP::Interface, PCAP::ProcessorEmpty>>(argv[1]);
    controller->start();

    std::cout << "Started" << std::endl;

    {
        using namespace PCAP::PCAPBuilder;
        LOG_BLOCK_E;
        auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
                    {Keys::Key_Eth_Mac_Src, Option{local_mac}},
                    {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
                    {Keys::Key_Ip_Src, Option{local_ip}},
                    {Keys::Key_Ip_Dst, Option{PCAP::IpAddress(std::string("255.255.255.255"))}},
                    {Keys::Key_Icmp_Code, Option{(unsigned char)0x00}},
                    {Keys::Key_Icmp_Type, Option{(unsigned char)0x08}}
                });
        for (int i = 0; i < N; ++i) {
            controller->write(package.getPackage(), package.getLength());
        }
    }
}