#pragma once

#include <string>
#include <memory>
#include <tuple>

#include <mysql/mysql.h>

#include "database.h"
#include <pqxx/pqxx>

class PostgresJobProvider : public JobProvider {
private:
    pqxx::connection c;
public:
    PostgresJobProvider( const std::string& server, const std::string& user, const std::string& password, const std::string& database );

public:
    std::shared_ptr<Job> fetchJob();
    void finishJob( std::shared_ptr<Job> job );
    void failJob( std::shared_ptr<Job> job );
    std::shared_ptr<TBSCertificate> fetchTBSCert( std::shared_ptr<Job> job );
    void writeBack( std::shared_ptr<Job> job, std::shared_ptr<SignedCertificate> res );
    std::pair<std::string, std::string> getRevocationInfo( std::shared_ptr<Job> job );
    void writeBackRevocation( std::shared_ptr<Job> job, std::string date );
};
