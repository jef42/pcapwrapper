#ifndef DBCOMMAND_H
#define DBCOMMAND_H

#include <string>
#include <sqlite3.h>

class DBCommand
{
public:
    bool execute() { return execute_impl(); }
    virtual ~DBCommand();

private:
    virtual bool execute_impl() = 0;
};

#endif
