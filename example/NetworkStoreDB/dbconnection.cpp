#include "dbconnection.h"

#include <iostream>

#include "dbcommand.h"

DBConnection::DBConnection(const std::string &db_name, const bool new_db)
    : m_db{nullptr} {
    if (!open(db_name))
        throw std::string{"could not open db"};

    if (new_db)
        create_tables();
}

DBConnection::~DBConnection() {
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

bool DBConnection::open(const std::string &db_name) {
    return sqlite3_open(db_name.c_str(), &m_db) == SQLITE_OK &&
           sqlite3_exec(m_db, "PRAGMA journal_mode=WAL", nullptr, nullptr,
                        nullptr) == SQLITE_OK;
}

bool DBConnection::create_tables() {
    char *errMsg = nullptr;
    return sqlite3_exec(m_db, "CREATE TABLE IF NOT EXISTS UDP(date LONG, "
                              "src_ip STR, dst_ip STR, src_port INTEGER, "
                              "dst_port INTEGER, data BLOB, data_size INT);",
                        nullptr, nullptr, &errMsg) == SQLITE_OK &&
           sqlite3_exec(m_db, "CREATE TABLE IF NOT EXISTS TCP(date LONG, "
                              "src_ip STR, dst_ip STR, src_port INTEGER, "
                              "dst_port INTEGER, data BLOB, data_size INT);",
                        nullptr, nullptr, &errMsg) == SQLITE_OK &&
           sqlite3_exec(m_db, "CREATE TABLE IF NOT EXISTS ICMP(date LONG, "
                              "src_ip STR, dst_ip STR, data BLOB, data_size "
                              "INT);",
                        nullptr, nullptr, &errMsg) == SQLITE_OK &&
           sqlite3_exec(m_db, "CREATE TABLE IF NOT EXISTS ARP(date LONG, "
                              "src_mac STR, src_ip STR, dst_mac STR, data "
                              "BLOB, data_size INT);",
                        nullptr, nullptr, &errMsg) == SQLITE_OK;
}

bool DBConnection::execute(const std::shared_ptr<DBCommand> &command) {
    return command->execute();
}
