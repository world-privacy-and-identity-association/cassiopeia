#pragma once

#include <string>
#include <memory>
#include <vector>

struct Job {
    std::string id;
    std::string target;
    std::string task;
    std::string from;
    std::string to;
};

struct SAN {
    std::string content;
    std::string type;
};

struct TBSCertificate {
    std::string CN;
    std::string subj;
    std::string md;
    std::string profile;
    std::string csr;
    std::string csr_type;
    std::string csr_content;
    std::vector<std::shared_ptr<SAN>> SANs;
};

class JobProvider {
public:
    virtual std::shared_ptr<Job> fetchJob() = 0;
    virtual bool finishJob( std::shared_ptr<Job> job ) = 0;
    virtual std::shared_ptr<TBSCertificate> fetchTBSCert( std::shared_ptr<Job> job ) = 0;
};
