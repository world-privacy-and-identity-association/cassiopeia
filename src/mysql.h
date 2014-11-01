#pragma once

#include <mysql/mysql.h>

#include <string>
#include <memory>
#include <tuple>

#include "database.h"

class MySQLJobProvider : public JobProvider {
private:
    static std::shared_ptr<int> lib_ref;

    std::shared_ptr<MYSQL> conn;

private:
    std::shared_ptr<MYSQL> _connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database );

public:
    MySQLJobProvider( const std::string& server, const std::string& user, const std::string& password, const std::string& database );
    ~MySQLJobProvider();

public:
    bool connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database );
    bool disconnect();

    std::string escape_string( const std::string& target );

    std::pair< int, std::shared_ptr<MYSQL_RES> > query( const std::string& query );

public:
    std::shared_ptr<Job> fetchJob();
    bool finishJob( std::shared_ptr<Job> job );
    std::shared_ptr<TBSCertificate> fetchTBSCert( std::shared_ptr<Job> job );
};
