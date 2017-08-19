#ifndef DNSENTRY_H
#define DNSENTRY_H

#include <string>
#include <chrono>
#include <ostream>

class DNSEntry {
public:
    DNSEntry(const std::string& website, std::chrono::time_point<std::chrono::system_clock> time);

    DNSEntry(const DNSEntry& rhs) = default;
    DNSEntry(DNSEntry&& rhs) = default;
    DNSEntry& operator=(const DNSEntry& rhs) = default;
    DNSEntry& operator=(DNSEntry&& rhs) = default;

    friend bool operator== (const DNSEntry& lhs, const DNSEntry& rhs) noexcept;
    friend bool operator!= (const DNSEntry& lhs, const DNSEntry& rhs) noexcept;
    friend std::ostream& operator<<(std::ostream& stream, const DNSEntry& entry);

    void update(std::chrono::time_point<std::chrono::system_clock> time);
    std::chrono::time_point<std::chrono::system_clock> get_time() const;
    int get_count() const;

private:
    std::string m_website;
    std::chrono::time_point<std::chrono::system_clock> m_time;
    int m_counter;
};

#endif
