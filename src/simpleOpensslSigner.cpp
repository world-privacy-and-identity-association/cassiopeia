#include "simpleOpensslSigner.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

extern std::vector<Profile> profiles;

std::shared_ptr<int> SimpleOpensslSigner::lib_ref(
    new int( SSL_library_init() ),
    []( int* ref ) {
        delete ref;

        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    } );

std::shared_ptr<X509> loadX509FromFile( std::string filename ) {
    FILE* f = fopen( filename.c_str(), "r" );

    if( !f ) {
        return std::shared_ptr<X509>();
    }

    X509* key = PEM_read_X509( f, NULL, NULL, 0 );
    fclose( f );

    if( !key ) {
        return std::shared_ptr<X509>();
    }

    return std::shared_ptr<X509>(
        key,
        []( X509 * ref ) {
            X509_free( ref );
        } );
}

std::shared_ptr<EVP_PKEY> loadPkeyFromFile( std::string filename ) {
    FILE* f = fopen( filename.c_str(), "r" );

    if( !f ) {
        return std::shared_ptr<EVP_PKEY>();
    }

    EVP_PKEY* key = PEM_read_PrivateKey( f, NULL, NULL, 0 );
    fclose( f );

    if( !key ) {
        return std::shared_ptr<EVP_PKEY>();
    }

    return std::shared_ptr<EVP_PKEY>(
        key,
        []( EVP_PKEY * ref ) {
            EVP_PKEY_free( ref );
        } );
}

SimpleOpensslSigner::SimpleOpensslSigner() {
    caCert = loadX509FromFile( profiles[0].cert );
    caKey = loadPkeyFromFile( profiles[0].key );
}

int serial = 10;

std::shared_ptr<SignedCertificate> SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    if( !caKey ) {
        throw "CA-key not found";
    }

    std::shared_ptr<X509Req> req = X509Req::parse( cert->csr_content );

    int i = req->verify();

    if( i < 0 ) {
        throw "Signature problems ... ";
    } else if( i == 0 ) {
        throw "Signature did not match";
    } else {
        std::cerr << "Signature ok" << std::endl;
    }

    // Construct the Certificate
    X509Cert c = X509Cert();
    std::shared_ptr<X509> retsh = std::shared_ptr<X509>( X509_new(), X509_free );
    X509* ret = retsh.get();

    if( !ret ) {
        throw "Creating X509 failed.";
    }

    c.setIssuerNameFrom( caCert );
    c.setPubkeyFrom( req );
    c.setSerialNumber( serial++ );
    c.setTimes( 0, 60 * 60 * 24 * 10 );
    c.setExtensions( caCert, cert->SANs );

    std::shared_ptr<SignedCertificate> output = c.sign( caKey );

    return output;
}
