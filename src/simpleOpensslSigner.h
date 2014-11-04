#pragma once

#include <openssl/ssl.h>

#include "database.h"
#include "signer.h"

class SimpleOpensslSigner : public Signer {
private:
    static std::shared_ptr<int> lib_ref;
    std::shared_ptr<EVP_PKEY> caKey;
    std::shared_ptr<X509> caCert;
    std::shared_ptr<BIGNUM> nextSerial( uint16_t profile );
public:
    SimpleOpensslSigner();
    ~SimpleOpensslSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
};
