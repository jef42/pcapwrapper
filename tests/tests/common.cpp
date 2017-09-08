#include "common.h"

#include <thread>

void wait_test_finished(std::chrono::milliseconds milli)
{
    std::this_thread::sleep_for(milli);
}