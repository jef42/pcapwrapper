#include "insertcommand.h"

#include <chrono>

InsertCommand::InsertCommand(std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::UDPPackage>& package)
    : m_stmt{nullptr},
    m_db{db}
{
    const std::string command = "INSERT INTO UDP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package->getSrcIp().to_string() + "\", \"" + package->getDstIp().to_string() + "\", " +
        std::to_string(package->getSrcPort()) + ", " +
        std::to_string(package->getDstPort()) + ", " +
        "?, " + std::to_string(package->getLength()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package->getPackage(), package->getLength(), SQLITE_STATIC);
}

InsertCommand::InsertCommand(std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::TCPPackage>& package)
{
    const std::string command = "INSERT INTO TCP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package->getSrcIp().to_string() + "\", \"" + package->getDstIp().to_string() + "\", " +
        std::to_string(package->getSrcPort()) + ", " +
        std::to_string(package->getDstPort()) + ", " +
        "?, " + std::to_string(package->getLength()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package->getPackage(), package->getLength(), SQLITE_STATIC);
}

InsertCommand::InsertCommand(std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::ICMPPackage>& package)
{
    const std::string command = "INSERT INTO ICMP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package->getSrcIp().to_string() + "\", \"" + package->getDstIp().to_string() + "\", "
        "?, " + std::to_string(package->getLength()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package->getPackage(), package->getLength(), SQLITE_STATIC);
}

InsertCommand::InsertCommand(std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::ARPPackage>& package)
{
    const std::string command = "INSERT INTO ARP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package->getSrcMac().to_string() + "\", \"" + package->getSrcIp().to_string() +"\",  \"" + package->getDstIp().to_string() + "\", " +
        "?, " + std::to_string(package->getLength()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package->getPackage(), package->getLength(), SQLITE_STATIC);
}

bool InsertCommand::execute_impl()
{
    sqlite3_step(m_stmt);
    sqlite3_finalize(m_stmt);
    return true;
}

unsigned long InsertCommand::get_real_time() const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>
        (std::chrono::system_clock::now().time_since_epoch()).count();
}
