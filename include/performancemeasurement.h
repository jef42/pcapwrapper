#ifndef PCAPPERFORMANCEMEASUREMENT_H
#define PCAPPERFORMANCEMEASUREMENT_H

#include <chrono>
#include <initializer_list>
#include <iostream>
#include <thread>

#define LOG_D(msg)                                                             \
    PCAP::Logging::log_helper<PCAP::Logging::LOG_LEVEL::Debug>(                \
        __PRETTY_FUNCTION__, "#", std::this_thread::get_id(), ":",             \
        PCAP::Logging::get_time(), " ", msg, "\n");
#define LOG_W(msg)                                                             \
    PCAP::Logging::log_helper<PCAP::Logging::LOG_LEVEL::Warning>(              \
        __PRETTY_FUNCTION__, "#", std::this_thread::get_id(), ":",             \
        PCAP::Logging::get_time(), " ", msg, "\n");
#define LOG_E(msg)                                                             \
    PCAP::Logging::log_helper<PCAP::Logging::LOG_LEVEL::Error>(                \
        __PRETTY_FUNCTION__, "#", std::this_thread::get_id(), ":",             \
        PCAP::Logging::get_time(), " ", msg, "\n");

#define LOG_BLOCK_D                                                            \
    PCAP::Logging::LogBlock<PCAP::Logging::LOG_LEVEL::Debug> bomb(             \
        __PRETTY_FUNCTION__, __LINE__, std::this_thread::get_id());
#define LOG_BLOCK_W                                                            \
    PCAP::Logging::LogBlock<PCAP::Logging::LOG_LEVEL::Warning> bomb(           \
        __PRETTY_FUNCTION__, __LINE__, std::this_thread::get_id());
#define LOG_BLOCK_E                                                            \
    PCAP::Logging::LogBlock<PCAP::Logging::LOG_LEVEL::Error> bomb(             \
        __PRETTY_FUNCTION__, __LINE__, std::this_thread::get_id());

namespace PCAP {
namespace Logging {

enum class LOG_LEVEL { Debug, Warning, Error, None };

// change this if you want to change logging level
static constexpr LOG_LEVEL current_level = LOG_LEVEL::Error;

template <LOG_LEVEL level> struct TO_LOG {
    static const bool result = current_level <= level ? true : false;
};

std::chrono::milliseconds::rep get_time();

template <typename T> static void log_print(T arg) { std::cout << arg; }

template <LOG_LEVEL level, typename... Args>
static typename std::enable_if<TO_LOG<level>::result>::type
log_helper(Args &&... args) {
    std::initializer_list<int>{(log_print(args), 0)...};
}

// create empty functions in casw we don't want to log anything
template <LOG_LEVEL level, typename... Args>
static typename std::enable_if<!TO_LOG<level>::result>::type
log_helper(Args &&...) {}

// add class to log to iostream the time it was alive
template <LOG_LEVEL level> class LogBlock {
  public:
    LogBlock(const char *function_name, size_t line_nr, std::thread::id id)
        : m_function_name{function_name}, m_line_nr{line_nr}, m_id{id} {
        m_start_time = std::chrono::high_resolution_clock::now();
        log_helper<level>(m_function_name, ":", m_line_nr, " ", m_id,
                          " Enter: ", "\n");
    }

    ~LogBlock() noexcept {
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - m_start_time;
        log_helper<level>(m_function_name, " ", m_id, " Exit: ",
                          duration.count(), "\n");
    }

  private:
    const char *m_function_name;
    size_t m_line_nr;
    std::thread::id m_id;
    std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>
        m_start_time;
};
}
}

#endif // PCAPPERFORMANCEMEASUREMENT_H
