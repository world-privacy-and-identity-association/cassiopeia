#pragma once

#include <memory>

#include "database.h"
#include "sslUtil.h"

class Signer {
public:
    virtual std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert ) = 0;
    virtual std::shared_ptr<X509_CRL> revoke( std::shared_ptr<CAConfig> ca, std::string serial ) = 0;
};
