#ifndef PCAPINTERFACETHREADSAFE_H
#define PCAPINTERFACETHREADSAFE_H

#include <mutex>

#include "../helpers/common.h"
#include "interface.h"

namespace PCAP {

class InterfaceThreadSafe : public Interface {
  public:
    explicit InterfaceThreadSafe(const std::string &name);

  private:
    int write_impl(const uchar *package, int len) override;

    static std::mutex m_mutex;
};
}

#endif
