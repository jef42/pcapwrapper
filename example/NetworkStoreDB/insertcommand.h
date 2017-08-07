#ifndef INSERTCOMMAND_H
#define INSERTCOMMAND_H

#include <string>
#include <memory>
#include <pcapwrapper/network/packages/tcppackage.h>
#include <pcapwrapper/network/packages/udppackage.h>
#include <pcapwrapper/network/packages/icmppackage.h>
#include <pcapwrapper/network/packages/arppackage.h>

#include "dbconnection.h"
#include "dbcommand.h"


class InsertCommand : public DBCommand
{
public:
    friend class DBConnection;

    explicit InsertCommand(const std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::UDPPackage>& package);
    explicit InsertCommand(const std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::TCPPackage>& package);
    explicit InsertCommand(const std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::ICMPPackage>& package);
    explicit InsertCommand(const std::shared_ptr<DBConnection>& db, std::unique_ptr<PCAP::ARPPackage>& package);
    virtual ~InsertCommand() = default;
private:
    sqlite3_stmt* m_stmt;
    std::shared_ptr<DBConnection> m_db;

    bool execute_impl();

    unsigned long get_real_time() const;
};

#endif
