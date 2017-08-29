#include "cookieworker.h"

#include <algorithm>
#include <fstream>
#include <ctime>
#include <sys/stat.h>
#include <unistd.h>
#include <ctime>
#include <map>
#include <iomanip>
#include <sstream>
#include <iostream>

const static std::string PATH = "/home/oroles/Programming/C++/Pcap/example/builds/";

std::string get_local_day() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%d-%m-%Y");
    return oss.str();
}

std::string create_dir() {
    struct stat st;
    std::string local_day = get_local_day();
    std::string path = PATH + get_local_day();
    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
    return local_day;
}

void append_to(const std::string& filename, const std::string& data) {
    std::ofstream stream(PATH + filename, std::ofstream::app);
    auto time = std::chrono::system_clock::to_time_t(std::chrono::high_resolution_clock::now());
    auto time_str = std::string(std::ctime(&time));
    time_str.pop_back();
    stream  << time_str << " " << data << "\n";
    stream.close();
}

CookieWorker::CookieWorker(PCAP::TCPPackage package) {
    m_worker_finished = false;
    m_worker = std::async(&CookieWorker::worker, this);
    m_src_ip = package.getSrcIp();
    m_file_name = create_dir() + "/" + m_src_ip.to_string();
    this->new_package(package);
}

void CookieWorker::new_package(PCAP::TCPPackage package) {
    std::string data = std::string((char*)package.getData(), package.getDataLength());

    std::unique_lock<std::mutex> lk(m_worker_mutex);
    m_payloads.emplace_back(data);
    m_worker_cond.notify_all();
}

void CookieWorker::finish() {
    m_worker_finished = true;
    m_worker.get();
}

PCAP::IpAddress CookieWorker::get_src_ip() const {
    return m_src_ip;
}

std::string get_website(const std::string& header) {
    auto host_index = header.find("Referer: ");
    auto host_end = header.find("\r\n", host_index);
    if (host_index != std::string::npos && host_end != std::string::npos) {
        return std::string(header, host_index, host_end-host_index);
    }
    return "";
}

std::string get_cookie(const std::string& header) {
    auto cookie_index = header.find("Cookie: ");
    auto cookie_end = header.find("\r\n", cookie_index);
    if (cookie_index != std::string::npos) {
        return std::string(header, cookie_index, cookie_end == std::string::npos ?
                                                                header.size() - cookie_index : cookie_end);
    }
    return "";
}

void CookieWorker::worker() {
    using namespace std::chrono_literals;

    while (!m_worker_finished) {
        std::unique_lock<std::mutex> lk(m_worker_mutex);
        m_worker_cond.wait_for(lk, 100ms, [this]{ return !m_payloads.empty() || m_worker_finished; });

        for (auto& payload : m_payloads) {
            auto index = payload.find("\r\n\r\n");
            if (index != std::string::npos) {
                std::string header = std::string(payload, 0, index);
                std::string website = get_website(header);
                std::string cookie = get_cookie(header);

                if (std::find(std::begin(m_websites), std::end(m_websites), website) == std::end(m_websites)) {
                    m_websites.push_back(website);
                }

                if (!website.empty() && !cookie.empty()) {
                    append_to(m_file_name, website);
                    append_to(m_file_name, cookie);
                }
            }
        }
        m_payloads.clear();
    }
}
