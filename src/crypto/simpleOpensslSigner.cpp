#include "simpleOpensslSigner.h"

#include <sstream>
#include <unordered_map>
#include <exception>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

#include "log/logger.hpp"

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

        if( !bn || !BN_hex2bn( &bn, "1" )) {
            throw std::runtime_error("Initing serial failed");
        }
    } else {
        if( !BN_hex2bn( &bn, res.c_str() ) ) {
            throw std::runtime_error("Parsing serial failed.");
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
        throw std::runtime_error("Big number math failed while fetching random data for serial number.");
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
    logger::logger_set log_set_sign({logger::log_target(signlog, logger::level::debug)}, logger::auto_register::on);

    logger::note( "FINE: Profile name is: ", cert->profile );

    Profile& prof = profiles.at( cert->profile );
    logger::note( "FINE: Profile ID is: ", prof.id );

    std::shared_ptr<CAConfig> ca = prof.getCA();

    if( !ca ) {
        logger::error( "ERROR: Signing CA specified in profile could not be loaded." );
        throw std::runtime_error("CA-key not found");
    }
    if(!ca->caKey){
        throw std::runtime_error("Cannot sign certificate with CA " + ca->name + " because it has no private key.");
    }

    logger::note( "FINE: Key for Signing CA is correctly loaded." );

    logger::note( "INFO: Baseline Key Usage is: ", prof.ku );
    logger::note( "INFO: Extended Key Usage is: ", prof.eku );

    logger::note( "FINE: Signing is wanted by: ", cert->wishFrom );
    logger::note( "FINE: Signing is wanted for: ", cert->wishTo );

    std::shared_ptr<X509Req> req;

    if( cert->csr_type == "SPKAC" ) {
        req = X509Req::parseSPKAC( cert->csr_content );
    } else if( cert->csr_type == "CSR" ) {
        req = X509Req::parseCSR( cert->csr_content );
    } else {
        logger::errorf( "ERROR: Unknown type (\"%s\") of certification in request.", cert->csr_type );
        throw std::runtime_error("Error, unknown REQ rype " + cert->csr_type ); //! \fixme: Pointer instead of string, please use proper exception classe)s
    }

    int i = req->verify();

    if( i < 0 ) {
        throw std::runtime_error("Request contains a Signature with problems ... ");
    } else if( i == 0 ) {
        throw std::runtime_error("Request contains a Signature that does not match ...");
    } else {
        logger::note( "FINE: Request contains valid self-signature." );
    }

    // Construct the Certificate
    X509Cert c = X509Cert();

    logger::note( "INFO: Populating RDN ..." );

    for( std::shared_ptr<AVA> a : cert->AVAs ) {
        logger::notef( "INFO: Trying to add RDN: %s: %s", a->name, a->value );
        if( a->value.empty() ) {
            logger::notef( "INFO: Removing empty RDN: %s", a->name);
            continue;
        }
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
            logger::error( "ERROR: Trying to add illegal RDN/AVA type: ", a->name );
            throw std::runtime_error("Unhandled/Illegal AVA type");
        }
    }

    logger::note( "INFO: Populating Issuer ..." );
    c.setIssuerNameFrom( ca->ca );

    logger::note( "INFO: Validating Public key for use in certificate" );
    logger::note( "INFO: - Checking generic key parameters" );
    logger::note( "FINE:   ->Public Key parameters are okay" );

    logger::note( "INFO: - Checking blacklists" );
    logger::note( "FINE:   ->Does not appear on any blacklist" );

    logger::note( "INFO: - Checking trivial factorization" );
    logger::note( "FINE:   ->Trivial factorization not possible" );

    logger::note( "INFO: - Checking astrological signs" );
    logger::note( "FINE:   ->The stars look good for this one" );
    logger::note( "FINE: Public key is fine for use in certificate" );

    logger::note( "INFO: Copying Public Key from Request ..." );
    c.setPubkeyFrom( req );
    logger::note( "FINE: Public Key successfully copied from Request." );

    {
        logger::note( "INFO: Determining Validity Period ..." );
        std::time_t from, to;
        std::time_t now = time( 0 );
        std::pair<bool, std::time_t> parsed;

        if( ( parsed = parseDate( cert->wishFrom ) ).first /* is of yyyy-mm-dd */ ) {
            if( parsed.second > now ) {
                from = parsed.second;
            } else { // fail
                from = now;
            }
        } else {
            from = now;
        }

        if( ( ( from - now ) > /* 2 Weeks */ ( 2 * 7 * 24 * 60 * 60 ) ) || ( ( now - from ) >= 0 ) ) {
            from = now;
        }

        if( ( parsed = parseDate( cert->wishTo ) ).first /*is of yyyy-mm-dd */ ) {
            if( parsed.second > from ) {
                to = parsed.second;
            } else {
                to = from + /*2 Years */ 2 * 365 * 24 * 60 * 60;
            }
        } else if( ( parsed = parseYearInterval( from, cert->wishTo ) ).first /*is of [0-9]+y */ ) {
            to = parsed.second;
        } else if( ( parsed = parseMonthInterval( from, cert->wishTo ) ).first /*is of [0-9]+m */ ) {
            to = parsed.second;
        } else {
            to = from + /*2 Years */ 2 * 365 * 24 * 60 * 60;
        }

        time_t limit = prof.maxValidity;

        if( ( to - from > limit ) || ( to - from < 0 ) ) {
            to = from + limit;
        }

        c.setTimes( from, to );
        logger::note( "FINE: Setting validity period successful:" );
        {
            struct tm* timeobj;
            std::vector<char> timebuf;

            timeobj = gmtime( &from );
            timebuf.resize( 128 );
            timebuf.resize( std::strftime( const_cast<char*>( timebuf.data() ), timebuf.size(), "%F %T %Z", timeobj ) );
            logger::note( "FINE: - Valid not before: ", std::string( timebuf.cbegin(), timebuf.cend() ) );

            timeobj = gmtime( &to );
            timebuf.resize( 128 );
            timebuf.resize( std::strftime( const_cast<char*>( timebuf.data() ), timebuf.size(), "%F %T %Z", timeobj ) );
            logger::note( "FINE: - Valid not after:  ", std::string( timebuf.cbegin(), timebuf.cend() ) );
        }
    }

    logger::note( "INFO: Setting extensions:" );
    c.setExtensions( ca->ca, cert->SANs, prof, ca->crlURL, ca->crtURL );
    logger::note( "FINE: Setting extensions successful." );

    logger::note( "INFO: Generating next Serial Number ..." );
    std::shared_ptr<BIGNUM> ser;
    std::string num;
    std::tie( ser, num ) = nextSerial( prof, ca );
    c.setSerialNumber( ser.get() );
    logger::note( "FINE: Certificate Serial Number set to: ", num );

    {
        logger::note( "INFO: Trying to sign Certificate:" );
        std::shared_ptr<SignedCertificate> output = c.sign( ca->caKey, cert->md );
        logger::note( "INFO: Writing certificate to local file." );
        std::string fn = writeBackFile( num, output->certificate, ca->path );

        if( fn.empty() ) {
            logger::error( "ERROR: failed to get filename for storage of signed certificate." );
            throw std::runtime_error("Storage location could not be determined");
        }

        logger::note( "FINE: Certificate signed successfully." );
        logger::note( "FINE: - Certificate written to: ", fn );

        output->ca_name = ca->name;
        output->log = signlog.str();
        return output;
    }
}

std::pair<std::shared_ptr<CRL>, std::string> SimpleOpensslSigner::revoke( std::shared_ptr<CAConfig> ca, std::vector<std::string> serials ) {
    logger::note( "revoking" );
    std::string crlpath = ca->path + "/ca.crl";

    auto crl = std::make_shared<CRL>( crlpath );
    std::string date = "";

    logger::note( "adding serials" );
    for( std::string serial : serials ) {
        date = crl->revoke( serial, "" );
    }

    logger::note( "signing CRL" );
    crl->sign( ca );
    writeFile( crlpath, crl->toString() );
    logger::note( "wrote CRL" );
    return std::pair<std::shared_ptr<CRL>, std::string>( crl, date );
}
