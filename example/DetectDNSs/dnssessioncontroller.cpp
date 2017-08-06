#include "dnssessioncontroller.h"

#include <iostream>
#include <algorithm>
#include <cctype>

static const int TRANSACTION_ID = 0;
static const int FLAGS = 2;
static const int QUESTIONS_COUNT = 4;
static const int ANSWERS_RRS = 6;
static const int AUTHORITY_RRS = 8;
static const int ADITIONAL_RRS = 10;
static const int QUERIES = 12; //Starts the data

DNSSessionController::DNSSessionController(const std::vector<PCAP::IpAddress>& target)
    : m_targets_ip{target}
{}

void DNSSessionController::newSession(const PCAP::Session&, std::unique_ptr<PCAP::UDPPackage> package) {
    if (std::find(m_targets_ip.begin(), m_targets_ip.end(), package->getSrcIp()) != m_targets_ip.end()) {
        const unsigned char* query = &(package->getData()[QUERIES+1]);
        std::string data = std::string((char*) query);
        std::transform(data.begin(), data.end(), data.begin(), [](auto c) {
            if (std::isalpha(c))
                return c;
            return '.';
        });
        static const std::string www = "www.";
        if (std::equal(www.begin(), www.end(), data.begin())) {
            std::lock_guard<std::mutex> lk(m_websites_mutex);
            m_websites[package->getSrcIp()].emplace_back(data, std::chrono::high_resolution_clock::now());
        }
    }
}

std::map<PCAP::IpAddress, std::vector<DNSEntry>> DNSSessionController::get_websites() {
    std::map<PCAP::IpAddress, std::vector<DNSEntry>> result;
    std::lock_guard<std::mutex> lk(m_websites_mutex);
    for( auto& entry : m_websites) {
        std::copy(entry.second.begin(), entry.second.end(), std::back_inserter(result[entry.first]));
    }
    m_websites.clear();
    return result;
}