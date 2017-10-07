#include "dnsworker.h"

#include <algorithm>
#include <ctime>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <pcapwrapper/helpers/common.h>

static const int TRANSACTION_ID = 0;
static const int FLAGS = 2;
static const int QUESTIONS_COUNT = 4;
static const int ANSWERS_RRS = 6;
static const int AUTHORITY_RRS = 8;
static const int ADITIONAL_RRS = 10;
static const int QUERIES = 12; // Starts the data

const static std::string PATH =
    "/home/oroles/Programming/C++/Pcap/example/builds/";

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

void append_to(const std::string &filename, const std::string &data) {
    std::ofstream stream(PATH + filename, std::ofstream::app);
    auto time = std::chrono::system_clock::to_time_t(
        std::chrono::high_resolution_clock::now());
    auto time_str = std::string(std::ctime(&time));
    time_str.pop_back();
    stream << time_str << " " << data << "\n";
    stream.close();
}

DNSWorker::DNSWorker(PCAP::UDPPackage package) {
    m_worker_finished = false;
    m_worker = std::async(&DNSWorker::worker, this);
    m_src_ip = package.get_src_ip();
    m_file_name = create_dir() + "/" + m_src_ip.to_string();
    this->new_session(package);
}

void DNSWorker::new_session(PCAP::UDPPackage package) {

    const PCAP::uchar *query = &(package.get_data()[QUERIES + 1]);
    std::string data = std::string((char *)query);

    std::unique_lock<std::mutex> lk(m_worker_mutex);
    m_tmp_websites.emplace_back(data);
    m_worker_cond.notify_all();
}

void DNSWorker::finish() {
    m_worker_finished = true;
    m_worker.get();
}

PCAP::IpAddress DNSWorker::get_src_ip() const { return m_src_ip; }

void DNSWorker::worker() {
    using namespace std::chrono_literals;

    while (!m_worker_finished) {
        std::unique_lock<std::mutex> lk(m_worker_mutex);
        m_worker_cond.wait_for(lk, 100ms, [this] {
            return !m_tmp_websites.empty() || m_worker_finished;
        });

        std::unique(m_tmp_websites.begin(), m_tmp_websites.end());
        for (auto &data : m_tmp_websites) {

            std::transform(data.begin(), data.end(), data.begin(), [](auto c) {
                if (std::isprint(c))
                    return c;
                return '.';
            });
            static const std::string www = "www.";
            static const std::string m = "m.";
            if (std::equal(www.begin(), www.end(), data.begin()) ||
                std::equal(m.begin(), m.end(), data.begin())) {
                append_to(m_file_name, data);
            }
        }

        m_tmp_websites.clear();
    }
}
