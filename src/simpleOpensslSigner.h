#pragma once

#include <openssl/ssl.h>

#include "database.h"
#include "sslUtil.h"
#include "signer.h"

class SimpleOpensslSigner : public Signer {
private:
    static std::shared_ptr<int> lib_ref;
    std::pair<std::shared_ptr<BIGNUM>, std::string> nextSerial( Profile& prof );
public:
    SimpleOpensslSigner();
    ~SimpleOpensslSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
    std::shared_ptr<X509_CRL> revoke( std::shared_ptr<CAConfig> ca, std::string serial );
};
