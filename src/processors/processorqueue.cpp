#include "../../include/processors/processorqueue.h"

namespace PCAP {

ProcessorQueue::ProcessorQueue()
    : m_stop{false}
{
    m_future = std::async(&ProcessorQueue::worker_impl, this);
}

void ProcessorQueue::callback_impl(const unsigned char *package, const pcap_pkthdr &header)
{
    m_queue.add(PCAP::RawPackage(package, header));
}

void ProcessorQueue::stop_worker()
{
    m_stop = true;
}

void ProcessorQueue::worker_impl()
{
    while (!m_stop) {
        RawPackage package = m_queue.pop();
        Processor::callback_impl(package.raw(), package.header());
    }
}

}
