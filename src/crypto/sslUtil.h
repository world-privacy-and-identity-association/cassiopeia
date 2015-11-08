#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cinttypes>
#include <ctime>

#include <openssl/ssl.h>

#include "db/database.h"

struct CAConfig {
    std::string path;
    std::string name;
    std::string crlURL;
    std::string crtURL;

    std::shared_ptr<X509> ca;
    std::shared_ptr<EVP_PKEY> caKey;
    std::shared_ptr<ASN1_TIME> notBefore;

    CAConfig( const std::string& name );

    bool crlNeedsResign();
};

struct Profile {
    uint16_t id;

    std::string eku;
    std::string ku;

    std::vector<std::shared_ptr<CAConfig>> ca;
    std::time_t maxValidity;
    std::shared_ptr<CAConfig> getCA() {
        for( auto it = ca.rbegin(); it != ca.rend(); it++ ) {
            if( X509_cmp_current_time( ( *it )->notBefore.get() ) < 0 ) {
                return *it;
            }
        }

        return ca[0];
    }
};

extern std::shared_ptr<int> ssl_lib_ref;

std::shared_ptr<X509> loadX509FromFile( const std::string& filename );
std::shared_ptr<EVP_PKEY> loadPkeyFromFile( const std::string& filename );

std::shared_ptr<SSL_CTX> generateSSLContext( bool server );
std::shared_ptr<BIO> openSerial( const std::string& name );
std::string timeToString( std::shared_ptr<ASN1_TIME> time );

void extractTimes( std::shared_ptr<X509> source, std::shared_ptr<SignedCertificate> cert );
