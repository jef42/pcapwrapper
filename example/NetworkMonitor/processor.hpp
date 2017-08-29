#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include <future>

class WorkerThread {
public:
    template <typename F, typename C>
    static std::future<void> start(F f, C c) {
        return std::async(std::launch::async, [&](){
            while (!c()) {
                f();
            }
            return;
        });
    }
};


#endif