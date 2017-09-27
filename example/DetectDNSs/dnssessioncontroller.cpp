#include "dnssessioncontroller.h"

#include <algorithm>
#include <cctype>
#include <iostream>

static const int TRANSACTION_ID = 0;
static const int FLAGS = 2;
static const int QUESTIONS_COUNT = 4;
static const int ANSWERS_RRS = 6;
static const int AUTHORITY_RRS = 8;
static const int ADITIONAL_RRS = 10;
static const int QUERIES = 12; // Starts the data

DNSSessionController::DNSSessionController(
    const std::vector<PCAP::IpAddress> &target)
    : m_targets_ip{target} {}

void DNSSessionController::new_session(const PCAP::Session &,
                                      PCAP::UDPPackage package) {
    if (std::find(m_targets_ip.begin(), m_targets_ip.end(),
                  package.get_src_ip()) != m_targets_ip.end()) {
        std::string data =
            std::string((char *)&(package.get_data()[QUERIES + 1]));
        std::transform(data.begin(), data.end(), data.begin(), [](auto c) {
            if (std::isalpha(c))
                return c;
            return '.';
        });
        static const std::string www = "www.";
        if (std::equal(www.begin(), www.end(), data.begin())) {
            std::lock_guard<std::mutex> lk(m_websites_mutex);
            m_websites[package.get_src_ip()].emplace_back(
                data, std::chrono::high_resolution_clock::now());
        }
    }
}

std::map<PCAP::IpAddress, std::vector<DNSEntry>>
DNSSessionController::get_websites() {
    std::map<PCAP::IpAddress, std::vector<DNSEntry>> result;
    std::lock_guard<std::mutex> lk(m_websites_mutex);
    for (auto &entry : m_websites) {
        std::copy(entry.second.begin(), entry.second.end(),
                  std::back_inserter(result[entry.first]));
    }
    m_websites.clear();
    return result;
}
