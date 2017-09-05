# pcapwrapper

## Motivation

This is a wrapper over `C` pcap library. The purpose of the library is to enable easy access to the network. It is easier to write/read/analyze packages that are sent over the network.

## Requirements

Because it is a wrapper over pcap library, it requires this library to be installed. The wrapper is built using `libpcap-dev 1.7.4-2` library, `g++` and `C++17` on Unix system. It doesn't work on Windows systems.

To managed to build the library, it is required `cmake` version `3.5`

One of the example programs requires `sqlite3`.

## Build

To build the library are required 4 steps
1. `mkdir build`
2. `cd build`
2. `cmake ..`
3. `make`

To be able to build the examples you need to install the library using the command `sudo make install` and will be added under `/usr/lib/pcapwrapper`

To build the examples are required the same 4 steps to build the library only that, the commands needs to be run from the directory `example`

This will populate the directory builds under example with all the executables files. Every example is needed to be run with the right privileges.

## Example 1.

To detect all the TCP packages that are seen by the network card:

First create a TCP package listener:
```
class TCPListener : public PCAP::PackageListener<PCAP::TCPPackage>
{
public:
    void receivedPackage(PCAP::TCPPackage package) override {
        //TODO
    }
};
```

After that create a controller and set the filter, add the listeners and you just need to start it after that.
```
auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(int_name);
auto tcp_listener = std::make_shared<TCPListener>();
controller->addListener(tcp_listener);
controller->setFilter("tcp");
controller->start();
```

It is possible to add multiple listeners and to listen to different packages at the same time.

## Example 2.

It is also possible to write packages in the network. Most of the examples are using this. For example to detect all the computers in the network it could use the ICMP protocol to send a broadcast ping and listen for replies.

So we need a ICMP package listener:
```
class ICMPListener : public PCAP::PackageListener<PCAP::ICMPPackage>
{
public:
    void receivedPackage(PCAP::ICMPPackage package) override {
        //TODO
    }
};
```

And also we need to add the listener to controller and to start the controller.
```
auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(int_name);
auto icmp_listener = std::make_shared<ICMPListener>();
controller->addListener(icmp_listener);
controller->setFilter("icmp");
controller->start();
```

Now we need to create the packages that will be send in the network. to create a map with the pairs, field values.
```
auto package = PCAP::PCAPBuilder::make_icmp(std::map<Keys, Option>{
    {Keys::Key_Eth_Mac_Src, Option{mac}},
    {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
    {Keys::Key_Ip_Src, Option{ip}},
    {Keys::Key_Ip_Dst, Option{dest_ip}},
    {Keys::Key_Icmp_Code, Option{(unsigned char)0x00}},
    {Keys::Key_Icmp_Type, Option{(unsigned char)0x08}}
});
package.recalculateChecksums(); //Recalculate checksums
controller->write(package.getPackage(), package.getLength()); //Sends package on network
```
## Example 3.

A more complicated example is to monitor the entire network. For a complete example check example NetworkMonitor.

First step is to detect the router MAC address. After that we need to detect the computers that are in the network. We can use ARP package to request for MAC addresses for all IPs in the network, and those that are up will reply with their MAC. And then for each IP we need to do the ARP Spoof, so we can receive the packages.

!OBS! Be careful when and where you use this method.

```
class ARPListener : public PCAP::PackageListener<PCAP::ARPPackage>
{
public:
    ARPListener(router_ip, router_mac, local_ip, local_mac);
    void receivedPackage(PCAP::ARPPackage package) override {
        send_arp_package(router_ip, local_mac, target_ip, target_mac);
        send_arp_package(local_ip, target_mac, router_ip, router_mac);
    }
};

auto controller = PCAP::Controller<PCAP::Interface, PCAP::Processor>::getController(int_name);
auto arp_listener = std::make_shared<ARPListener>();
controller->addListener(arp_listener);
controller->setFilter("arp");
controller->start();

for (const auto& target_ip : ips) {
    auto package = PCAP::PCAPBuilder::make_apr(std::map<Keys, Option>{
        {Keys::Key_Eth_Mac_Src, Option(local_mac)},
        {Keys::Key_Eth_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
        {Keys::Key_Arp_Mac_Src, Option(local_mac)},
        {Keys::Key_Arp_Mac_Dst, Option{PCAP::MacAddress(std::string("FF:FF:FF:FF:FF:FF"))}},
        {Keys::Key_Arp_Opcode, Option((unsigned char)0x01)},
        {Keys::Key_Ip_Src, Option(local_ip)},
        {Keys::Key_Ip_Dst, Option(target_ip)}});
    controller->write(package.getPackage(), package.getLength());
}
```

