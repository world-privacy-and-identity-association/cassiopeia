#pragma once

#include <memory>

#include "database.h"

class Signer {
public:
    virtual void sign( std::shared_ptr<TBSCertificate> cert ) = 0;
};
