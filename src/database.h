#pragma once

#include <string>
#include <memory>

struct Job {
    std::string id;
    std::string task;
    std::string from;
    std::string to;
};

class JobProvider {
public:
    virtual std::shared_ptr<Job> fetchJob() = 0;
    virtual bool finishJob( std::shared_ptr<Job> job ) = 0;
};
