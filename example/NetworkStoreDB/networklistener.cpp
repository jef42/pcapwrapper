#include "networklistener.h"

#include <iostream>

#include "insertcommand.h"

NetworkListener::NetworkListener(
    const std::shared_ptr<DBConnection> &db_connection)
    : m_db_connection{db_connection} {}

void NetworkListener::receive_package(PCAP::TCPPackage package) {
    m_db_connection->execute(
        std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receive_package(PCAP::UDPPackage package) {
    m_db_connection->execute(
        std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receive_package(PCAP::ICMPPackage package) {
    m_db_connection->execute(
        std::make_shared<InsertCommand>(m_db_connection, package));
}

void NetworkListener::receive_package(PCAP::ARPPackage package) {
    m_db_connection->execute(
        std::make_shared<InsertCommand>(m_db_connection, package));
}
