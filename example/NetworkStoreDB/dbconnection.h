#ifndef DBCONNECTION_H
#define DBCONNECTION_H

#include <memory>
#include <sqlite3.h>
#include <string>

#include "dbcommand.h"

class DBConnection {
  public:
    friend class InsertCommand;

    DBConnection(const std::string &db_name, const bool new_db = {true});
    ~DBConnection();

    bool execute(const std::shared_ptr<DBCommand> &command);

  private:
    bool open(const std::string &db_name);
    bool create_tables();

    sqlite3 *m_db;
};

#endif
