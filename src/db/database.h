#pragma once

#include <string>
#include <memory>
#include <vector>

struct Job {
    std::string id;
    std::string warning;
    std::string target;
    std::string task;
    std::string from;
    std::string to;
};

struct SAN {
    std::string content;
    std::string type;
};

struct AVA {
    std::string name;
    std::string value;
};

struct TBSCertificate {
    std::string md;
    std::string profile;

    /**
     * CSR path
     */
    std::string csr;
    std::string csr_type;
    std::string csr_content;
    std::vector<std::shared_ptr<SAN>> SANs;
    std::vector<std::shared_ptr<AVA>> AVAs;

    std::string wishFrom;
    std::string wishTo;

    std::string ocspCA;
};

struct SignedCertificate {
    std::string certificate;
    std::string serial;
    std::string before;
    std::string after;
    std::string pkHash;
    std::string certHash;
    std::string crt_name;
    std::string log;
    std::string ca_name;
};

class JobProvider {
public:
    virtual ~JobProvider() = default;
    virtual std::shared_ptr<Job> fetchJob() = 0;
    virtual void finishJob( std::shared_ptr<Job> job ) = 0;
    virtual void failJob( std::shared_ptr<Job> job ) = 0;
    virtual std::shared_ptr<TBSCertificate> fetchTBSCert( std::shared_ptr<Job> job ) = 0;
    virtual void writeBack( std::shared_ptr<Job> job, std::shared_ptr<SignedCertificate> res ) = 0;
    virtual std::pair<std::string, std::string> getRevocationInfo( std::shared_ptr<Job> job ) = 0;
    virtual void writeBackRevocation( std::shared_ptr<Job> job, std::string date ) = 0;
};
