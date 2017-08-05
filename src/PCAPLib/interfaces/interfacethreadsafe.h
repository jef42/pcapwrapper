#ifndef PCAPINTERFACETHREADSAFE_H
#define PCAPINTERFACETHREADSAFE_H

#include <mutex>

#include "interface.h"

namespace PCAP {

class InterfaceThreadSafe : public Interface {
public:
    InterfaceThreadSafe(const std::string& name);

private:
    virtual int write_impl(const unsigned char* package, int len);

    static std::mutex m_mutex;
};

}

#endif
