#pragma once

#include <memory>
#include <vector>

#include <openssl/ssl.h>

#include "db/database.h"
#include "crypto/sslUtil.h"

class X509Req {
private:
    std::shared_ptr<EVP_PKEY> pk;
    std::shared_ptr<X509_REQ> req;
    std::shared_ptr<NETSCAPE_SPKI> spki;
    X509Req( X509_REQ* csr );
    X509Req( std::string spkac );
public:
    static std::shared_ptr<X509Req> parseCSR( std::string content );
    static std::shared_ptr<X509Req> parseSPKAC( std::string content );
    int verify();
    std::shared_ptr<EVP_PKEY> getPkey() const;
};

class X509Cert {
private:
    std::shared_ptr<X509> target;
    std::shared_ptr<X509_NAME> subject;
public:
    X509Cert();
    void addRDN( int nid, std::string data );
    void setIssuerNameFrom( std::shared_ptr<X509> ca );
    void setPubkeyFrom( std::shared_ptr<X509Req> r );
    void setSerialNumber( BIGNUM* num );
    void setExtensions( std::shared_ptr<X509> caCert, std::vector<std::shared_ptr<SAN>>& sans, Profile& prof );
    void setTimes( uint32_t before, uint32_t after );
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<EVP_PKEY> caKey, std::string signAlg );
};
