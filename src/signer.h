#pragma once

#include <memory>

#include "database.h"

class Signer {
public:
    virtual std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert ) = 0;
};
