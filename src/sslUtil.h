#pragma once
#include <openssl/ssl.h>
#include <memory>

struct Profile {
    std::string cert;
    std::string key;
    std::string eku;
    std::string ku;

    std::shared_ptr<X509> ca;
    std::shared_ptr<EVP_PKEY> caKey;
};

extern std::shared_ptr<int> ssl_lib_ref;

std::shared_ptr<X509> loadX509FromFile( std::string filename );
std::shared_ptr<EVP_PKEY> loadPkeyFromFile( std::string filename );

std::shared_ptr<SSL_CTX> generateSSLContext( bool server );
std::shared_ptr<BIO> openSerial( const char* name );
