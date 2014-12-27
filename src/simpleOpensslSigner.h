#pragma once

#include <openssl/ssl.h>

#include "database.h"
#include "sslUtil.h"
#include "signer.h"

class SimpleOpensslSigner : public Signer {
private:
    static std::shared_ptr<int> lib_ref;
    Profile& prof;
    std::shared_ptr<BIGNUM> nextSerial( uint16_t profile );
public:
    SimpleOpensslSigner( Profile& prof );
    ~SimpleOpensslSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
};
