#include "insertcommand.h"

#include <chrono>

InsertCommand::InsertCommand(const std::shared_ptr<DBConnection> &db,
                             PCAP::UDPPackage package)
    : m_stmt{nullptr}, m_db{db} {
    const std::string command =
        "INSERT INTO UDP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package.get_src_ip().to_string() + "\", \"" +
        package.get_dst_ip().to_string() + "\", " +
        std::to_string(package.get_src_port()) + ", " +
        std::to_string(package.get_dst_port()) + ", " + "?, " +
        std::to_string(package.get_length()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package.get_package(), package.get_length(),
                      SQLITE_STATIC);
}

InsertCommand::InsertCommand(const std::shared_ptr<DBConnection> &db,
                             PCAP::TCPPackage package) {
    const std::string command =
        "INSERT INTO TCP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package.get_src_ip().to_string() + "\", \"" +
        package.get_dst_ip().to_string() + "\", " +
        std::to_string(package.get_src_port()) + ", " +
        std::to_string(package.get_dst_port()) + ", " + "?, " +
        std::to_string(package.get_length()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package.get_package(), package.get_length(),
                      SQLITE_STATIC);
}

InsertCommand::InsertCommand(const std::shared_ptr<DBConnection> &db,
                             PCAP::ICMPPackage package) {
    const std::string command = "INSERT INTO ICMP VALUES(" +
                                std::to_string(get_real_time()) + ", \"" +
                                package.get_src_ip().to_string() + "\", \"" +
                                package.get_dst_ip().to_string() + "\", "
                                                                 "?, " +
                                std::to_string(package.get_length()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package.get_package(), package.get_length(),
                      SQLITE_STATIC);
}

InsertCommand::InsertCommand(const std::shared_ptr<DBConnection> &db,
                             PCAP::ARPPackage package) {
    const std::string command =
        "INSERT INTO ARP VALUES(" + std::to_string(get_real_time()) + ", \"" +
        package.get_src_mac().to_string() + "\", \"" +
        package.get_src_ip().to_string() + "\",  \"" +
        package.get_dst_ip().to_string() + "\", " + "?, " +
        std::to_string(package.get_length()) + " );";
    sqlite3_prepare_v2(db->m_db, command.c_str(), -1, &m_stmt, nullptr);
    sqlite3_bind_blob(m_stmt, 1, package.get_package(), package.get_length(),
                      SQLITE_STATIC);
}

bool InsertCommand::execute_impl() {
    sqlite3_step(m_stmt);
    sqlite3_finalize(m_stmt);
    return true;
}

ulong InsertCommand::get_real_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
