#pragma once

#include <memory>
#include <vector>

#include <openssl/ssl.h>

#include "database.h"

class X509Req {
private:
    std::shared_ptr<EVP_PKEY> pk;
    std::shared_ptr<X509_REQ> req;
    X509Req( X509_REQ* csr );
public:
    static std::shared_ptr<X509Req> parse( std::string filename );
    int verify();
    std::shared_ptr<EVP_PKEY> getPkey();
};

class X509Cert {
private:
    std::shared_ptr<X509> target;
public:
    X509Cert();
    void setIssuerNameFrom( std::shared_ptr<X509> ca );
    void setPubkeyFrom( std::shared_ptr<X509Req> r );
    void setSerialNumber( int num );
    void setExtensions( std::shared_ptr<X509> caCert, std::vector<std::shared_ptr<SAN>>& sans );
    void setTimes( long before, long after );
    std::string sign( std::shared_ptr<EVP_PKEY> caKey );
};
