#include "networklistener.h"

#include <iostream>

#include "insertcommand.h"

NetworkListener::NetworkListener(const std::shared_ptr<DBConnection>& db_connection)
    : m_db_connection{db_connection}
{

}

void NetworkListener::receivedPackage(PCAP::TCPPackage package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(PCAP::UDPPackage package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(PCAP::ICMPPackage package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receivedPackage(PCAP::ARPPackage package)
{
    m_db_connection->execute(std::make_shared<InsertCommand>(m_db_connection, package));
}
