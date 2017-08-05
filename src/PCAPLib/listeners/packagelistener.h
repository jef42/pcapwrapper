#ifndef PCAPPACKAGELISTENER_H
#define PCAPPACKAGELISTENER_H

#include <memory>

namespace PCAP {

template <typename T>
class PackageListener {
  public:
    virtual void receivedPackage(std::unique_ptr<T> package) = 0;
};

}
#endif // PCAPPACKAGELISTENER_H
