#include "dnsentry.h"

#include <ctime>

DNSEntry::DNSEntry(const std::string &website,
                   std::chrono::time_point<std::chrono::system_clock> time)
    : m_website{website}, m_time{time}, m_counter{1} {}

void DNSEntry::update(std::chrono::time_point<std::chrono::system_clock> time) {
    m_time = time;
    ++m_counter;
}

std::chrono::time_point<std::chrono::system_clock> DNSEntry::get_time() const {
    return m_time;
}

int DNSEntry::get_count() const { return m_counter; }

bool operator==(const DNSEntry &lhs, const DNSEntry &rhs) noexcept {
    return lhs.m_website == rhs.m_website;
}

bool operator!=(const DNSEntry &lhs, const DNSEntry &rhs) noexcept {
    return !(lhs.m_website == rhs.m_website);
}

std::ostream &operator<<(std::ostream &stream, const DNSEntry &entry) {
    std::time_t time = std::chrono::system_clock::to_time_t(entry.m_time);
    stream << entry.m_website << " " << entry.m_counter << " "
           << std::string(std::ctime(&time));
    return stream;
}
