#include "simpleOpensslSigner.h"

#include <iostream>
#include <sstream>
#include <unordered_map>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#include "X509.h"
#include "util.h"
#include "sslUtil.h"

extern std::unordered_map<std::string, Profile> profiles;

std::shared_ptr<int> SimpleOpensslSigner::lib_ref = ssl_lib_ref;

SimpleOpensslSigner::SimpleOpensslSigner() {
}

SimpleOpensslSigner::~SimpleOpensslSigner() {
}

std::pair<std::shared_ptr<BIGNUM>, std::string> SimpleOpensslSigner::nextSerial( Profile& prof, std::shared_ptr<CAConfig> ca ) {
    uint16_t profile = prof.id;
    std::string res = readFile( ca->path + "/serial" );

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

    writeFile( ca->path + "/serial", serStr.get() );

    return std::pair<std::shared_ptr<BIGNUM>, std::string>( std::shared_ptr<BIGNUM>( BN_bin2bn( data.get(), len + 4 + 16 , 0 ), BN_free ), std::string( serStr.get() ) );
}

std::shared_ptr<SignedCertificate> SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    std::stringstream signlog;

    signlog << "FINE: profile is " << cert->profile << std::endl;

    Profile& prof = profiles.at( cert->profile );
    std::shared_ptr<CAConfig> ca = prof.getCA();

    if( !ca ) {
        throw "CA-key not found";
    }

    signlog << "FINE: CA-key is correctly loaded." << std::endl;
    signlog << "FINE: Profile id is: " << prof.id << std::endl;
    signlog << "FINE: ku is: " << prof.ku << std::endl;
    signlog << "FINE: eku is: " << prof.eku << std::endl;

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
        signlog << "FINE: Signature ok" << std::endl;
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
        signlog << "Addings RDN: " << a->name << ": " << a->value << std::endl;

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

    c.setIssuerNameFrom( ca->ca );
    c.setPubkeyFrom( req );

    std::shared_ptr<BIGNUM> ser;
    std::string num;
    std::tie( ser, num ) = nextSerial( prof, ca );
    c.setSerialNumber( ser.get() );
    c.setTimes( 0, 60 * 60 * 24 * 10 );
    signlog << "FINE: Setting extensions." << std::endl;
    c.setExtensions( ca->ca, cert->SANs, prof );
    signlog << "FINE: Signed" << std::endl;
    std::shared_ptr<SignedCertificate> output = c.sign( ca->caKey, cert->md );
    signlog << "FINE: all went well" << std::endl;
    signlog << "FINE: crt went to: " << writeBackFile( num, output->certificate, ca->path ) << std::endl;
    output->ca_name = ca->name;
    output->log = signlog.str();
    return output;
}

std::pair<std::shared_ptr<CRL>, std::string> SimpleOpensslSigner::revoke( std::shared_ptr<CAConfig> ca, std::string serial ) {
    std::string crlpath = ca->path + "/ca.crl";

    std::shared_ptr<CRL> crl( new CRL( crlpath ) );
    std::string date = crl->revoke( serial, "" );
    crl->sign( ca );
    writeFile( crlpath, crl->toString() );
    return std::pair<std::shared_ptr<CRL>, std::string>( crl, date );
}
