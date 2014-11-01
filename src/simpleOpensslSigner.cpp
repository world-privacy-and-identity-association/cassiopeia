#include "simpleOpensslSigner.h"

#include <iostream>
#include <fstream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#include "X509.h"

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

SimpleOpensslSigner::~SimpleOpensslSigner() {
}

std::shared_ptr<BIGNUM> SimpleOpensslSigner::nextSerial() {
    std::ifstream serialif( "serial" );
    std::string res;
    serialif >> res;
    serialif.close();

    BIGNUM* bn = 0;

    if( res == "" ) {
        bn = BN_new();

        if( !bn ) {
            throw "Initing serial failed";
        }
    } else {
        if( !BN_hex2bn( &bn, res.c_str() + 1 ) ) {
            throw "Parsing serial failed.";
        }
    }

    std::shared_ptr<BIGNUM> serial = std::shared_ptr<BIGNUM>( bn, BN_free );

    std::shared_ptr<unsigned char> data = std::shared_ptr<unsigned char>( ( unsigned char* ) malloc( BN_num_bytes( serial.get() ) + 20 ), free );
    int len = BN_bn2bin( serial.get(), data.get() );
    data.get()[len] = 0x0;
    data.get()[len + 1] = 0x0; // profile id
    data.get()[len + 2] = 0x0;
    data.get()[len + 3] = 0x0; // signer id

    if( !RAND_bytes( data.get() + len + 4, 16 ) || !BN_add_word( serial.get(), 1 ) ) {
        throw "Big number math failed while calcing serials.";
    }

    char* serStr = BN_bn2hex( serial.get() );
    std::ofstream serialf( "serial" );
    serialf << serStr;
    serialf.close();
    OPENSSL_free( serStr );

    return std::shared_ptr<BIGNUM>( BN_bin2bn( data.get(), len + 4 + 16 , 0 ), BN_free );
}

std::shared_ptr<SignedCertificate> SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    if( !caKey ) {
        throw "CA-key not found";
    }

    std::shared_ptr<X509Req> req;

    if( cert->csr_type == "SPKAC" ) {
        req = X509Req::parseSPKAC( cert->csr_content );
    } else if( cert->csr_type == "CSR" ) {
        req = X509Req::parse( cert->csr_content );
    } else {
        throw "Error, unknown REQ rype " + ( cert->csr_type );
    }

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

    X509_NAME* subjectP = X509_NAME_new();

    if( !subjectP ) {
        throw "malloc failure";
    }

    for( std::shared_ptr<AVA> a : cert->AVAs ) {
        if( a->name == "CN" ) {
            c.addRDN( NID_commonName, a->value );
        } else if( a->name == "EMAIL" ) {
            c.addRDN( NID_pkcs9_emailAddress, a->value );
        } else {
            throw "unknown AVA-type";
        }
    }

    c.setIssuerNameFrom( caCert );
    c.setPubkeyFrom( req );
    std::shared_ptr<BIGNUM> ser = nextSerial();
    c.setSerialNumber( ser.get() );
    c.setTimes( 0, 60 * 60 * 24 * 10 );
    c.setExtensions( caCert, cert->SANs );

    std::shared_ptr<SignedCertificate> output = c.sign( caKey );

    return output;
}
