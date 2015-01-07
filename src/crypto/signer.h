#pragma once

#include <memory>

#include "db/database.h"
#include "crypto/sslUtil.h"
#include "crypto/CRL.h"

class Signer {
public:
    virtual std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert ) = 0;
    virtual std::pair<std::shared_ptr<CRL>, std::string> revoke( std::shared_ptr<CAConfig> ca, std::string serial ) = 0;
};
