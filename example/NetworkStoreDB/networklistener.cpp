#include "networklistener.h"

#include <iostream>

#include "insertcommand.h"

NetworkListener::NetworkListener(const std::shared_ptr<DBConnection>& db_connection)
    : m_db_connection{db_connection}
{

}

void NetworkListener::receivedPackage(std::unique_ptr<PCAP::TCPPackage> package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(std::unique_ptr<PCAP::UDPPackage> package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(std::unique_ptr<PCAP::ICMPPackage> package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(std::unique_ptr<PCAP::ARPPackage> package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}
