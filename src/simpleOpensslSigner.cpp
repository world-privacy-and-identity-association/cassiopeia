#include "simpleOpensslSigner.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#include "X509.h"
#include "util.h"
#include "sslUtil.h"

extern std::vector<Profile> profiles;

std::shared_ptr<int> SimpleOpensslSigner::lib_ref = ssl_lib_ref;

SimpleOpensslSigner::SimpleOpensslSigner( Profile& prof ) : prof( prof ) {
}

SimpleOpensslSigner::~SimpleOpensslSigner() {
}

std::shared_ptr<BIGNUM> SimpleOpensslSigner::nextSerial( uint16_t profile ) {
    std::string res = readFile( "serial" );

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
    data.get()[len + 1] = 0x0; // signer id

    data.get()[len + 2] = profile >> 8;
    data.get()[len + 3] = profile & 0xFF; // profile id

    if( !RAND_bytes( data.get() + len + 4, 16 ) || !BN_add_word( serial.get(), 1 ) ) {
        throw "Big number math failed while calcing serials.";
    }

    std::shared_ptr<char> serStr = std::shared_ptr<char>(
        BN_bn2hex( serial.get() ),
        []( char* ref ) {
            OPENSSL_free( ref );
        } );
    writeFile( "serial", serStr.get() );

    return std::shared_ptr<BIGNUM>( BN_bin2bn( data.get(), len + 4 + 16 , 0 ), BN_free );
}

std::shared_ptr<SignedCertificate> SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    if( !prof.ca ) {
        throw "CA-key not found";
    }

    std::shared_ptr<X509Req> req;

    if( cert->csr_type == "SPKAC" ) {
        req = X509Req::parseSPKAC( cert->csr_content );
    } else if( cert->csr_type == "CSR" ) {
        req = X509Req::parseCSR( cert->csr_content );
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
        } else if( a->name == "C" ) {
            c.addRDN( NID_countryName, a->value );
        } else if( a->name == "L" ) {
            c.addRDN( NID_localityName, a->value );
        } else if( a->name == "ST" ) {
            c.addRDN( NID_stateOrProvinceName, a->value );
        } else if( a->name == "O" ) {
            c.addRDN( NID_organizationName, a->value );
        } else if( a->name == "OU" ) {
            c.addRDN( NID_organizationalUnitName, a->value );
        } else {
            throw "unknown AVA-type";
        }
    }

    c.setIssuerNameFrom( prof.ca );
    c.setPubkeyFrom( req );
    long int profile = strtol( cert->profile.c_str(), 0, 10 );

    if( profile > 0xFFFF || profile < 0 || ( profile == 0 && cert->profile != "0" ) ) {
        throw "invalid profile id";
    }

    std::shared_ptr<BIGNUM> ser = nextSerial( profile );
    c.setSerialNumber( ser.get() );
    c.setTimes( 0, 60 * 60 * 24 * 10 );
    c.setExtensions( prof.ca, cert->SANs );

    std::shared_ptr<SignedCertificate> output = c.sign( prof.caKey, cert->md );

    return output;
}
