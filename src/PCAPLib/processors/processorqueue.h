#ifndef PCAPPROCESSORQUEUE_H
#define PCAPPROCESSORQUEUE_H

#include "processor.h"
#include <future>

#include "queue/queue.hpp"
#include "queue/rawpackage.h"

namespace PCAP {

class ProcessorQueue : public PCAP::Processor {
public:
    ProcessorQueue();
    void stop_worker();
private:
    virtual void callback_impl(const unsigned char *package, const pcap_pkthdr &header) override;
    void worker_impl();

    PCAP::Queue<PCAP::RawPackage> m_queue;
    std::future<void> m_future;
    bool m_stop;
};

}

#endif // PCAPPROCESSORQUEUE_H
