#include "isup.h"

#include <algorithm>
#include <iostream>

IsUp::IsUp(const std::shared_ptr<ForwardPackage>& forward_package, 
           PCAP::IpAddress local_ip, 
           PCAP::MacAddress local_mac, 
           const std::string &interface)
 : m_forward_package{forward_package}
 , m_local_ip{local_ip}
 , m_local_mac{local_mac}
 , m_interface{interface}
 , m_stop_worker{false}
{
    m_worker = std::async(&IsUp::worker_impl, this);
}

IsUp::~IsUp() {
    m_stop_worker = true;
    m_worker.get();
}

void IsUp::stop() {
    m_stop_worker = true;
}

void IsUp::addTarget(PCAP::IpAddress ip, PCAP::MacAddress mac) {
    std::lock_guard<std::mutex> lk{m_received_targets_mtx};
    bool exists = false;
    for (auto t : m_received_targets) {
        if ((std::get<0>(t) == ip) && (std::get<1>(t) == mac)) {
            exists = true;
            break;
        }
    }
    if (!exists)
        m_received_targets.push_back(std::make_tuple(ip, mac));
}

void IsUp::worker_impl() {
    while (!m_stop_worker) {

        //wait for replies
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(20s);

        if (!m_stop_worker)
        {
            std::lock_guard<std::mutex> lk{m_received_targets_mtx};

            //we need to tell him to stop the threads because the target is not online anymore
            for (auto& target : m_targets) {
                auto it = std::find_if(m_received_targets.begin(), m_received_targets.end(), [&target](auto& received_target){
                    return std::get<0>(target) == std::get<0>(received_target) &&
                            std::get<1>(target) == std::get<1>(received_target); });
                //need to notify and clean local cache when the target goes offline so next time when gets online to create again the thread
                if (it == m_received_targets.end()) {
                    m_forward_package->stopClient(std::get<0>(target), std::get<1>(target));
                }
            }
            m_targets.clear();
            std::copy(std::begin(m_received_targets), std::end(m_received_targets), std::back_inserter(m_targets));
            m_received_targets.clear();
        }
    }
}
