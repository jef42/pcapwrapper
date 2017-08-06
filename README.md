# pcapwrapper

## Motivation

This is a wrapper over `C` pcap library. The purpose of the library is to enable easy access to the network. It is easier to write/read/analyze packages that are sent over the network.

## Requirements

Because it is a wrapper over pcap library, it requires this library to be installed. The wrapper is built using `libpcap-dev 1.7.4-2` library, `g++` and `C++17` on Unix system. It doesn't work on Windows systems.

One of the example programs requires `sqlite3`.

## Build

Select the path were to install the library using the variables `INSTALL_INCLUDE_PATH` and `INSTALL_LIB_PATH` in Makefile, otherwise is using the default values which is `/usr/include/pcapwrapper` respectively `/usr/lib/pcapwrapper`.

It is easy to build, just go where is the Makefile and:
```
make
````

In case to build the examples change inside `example` directory and run:
```
make
```

This will populate the directory builds with all the executables files. Every example it is needed to be run as `sudo`.