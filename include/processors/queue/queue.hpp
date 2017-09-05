#ifndef QUEUE_H
#define QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <type_traits>

namespace PCAP {

template <typename T>
class Queue {
public:
    void add(const T v) {
        std::unique_lock<std::mutex> lk{m_lock};
        m_queue.push(v);
        m_condition.notify_all();
    }

    bool is_empty() const {
        std::unique_lock<std::mutex> lk{m_lock};
        return m_queue.empty();
    }

    T pop() {
        std::unique_lock<std::mutex> lk{m_lock};
        while (m_queue.empty()) {
            m_condition.wait(lk);
        }
        T val = m_queue.front();
        m_queue.pop();
        return val;
    }

private:
    std::queue<T> m_queue;
    mutable std::mutex m_lock;
    std::condition_variable m_condition;
};

template <typename T>
class Queue<T*>{};

}

#endif // QUEUE_H
