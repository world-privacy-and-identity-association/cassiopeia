#pragma once

#include "database.h"
#include "signer.h"
#include <openssl/ssl.h>

class SimpleOpensslSigner : public Signer {
private:
    static std::shared_ptr<int> lib_ref;
    static std::shared_ptr<EVP_PKEY> caKey;
    static std::shared_ptr<X509> caCert;
public:
    void sign( std::shared_ptr<TBSCertificate> cert );
};
