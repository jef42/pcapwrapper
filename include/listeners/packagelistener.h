#ifndef PCAPPACKAGELISTENER_H
#define PCAPPACKAGELISTENER_H

namespace PCAP {

template <typename T> class PackageListener {
  public:
    virtual void receive_package(T package) = 0;
};
}
#endif // PCAPPACKAGELISTENER_H
