#pragma once

#include <openssl/ssl.h>

#include "db/database.h"
#include "crypto/sslUtil.h"
#include "crypto/signer.h"
#include "crypto/CRL.h"

class SimpleOpensslSigner : public Signer {
private:
    static std::shared_ptr<int> lib_ref;
    std::pair<std::shared_ptr<BIGNUM>, std::string> nextSerial( Profile& prof, std::shared_ptr<CAConfig> ca );
public:
    SimpleOpensslSigner();
    ~SimpleOpensslSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
    std::pair<std::shared_ptr<CRL>, std::string> revoke( std::shared_ptr<CAConfig> ca, std::vector<std::string> serial );
};
