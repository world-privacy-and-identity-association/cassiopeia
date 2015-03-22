#include "simpleOpensslSigner.h"

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
        if( !BN_hex2bn( &bn, res.c_str() ) ) {
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
        throw "Big number math failed while fetching random data for serial number.";
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
    signlog << "FINE: Profile id is: " << prof.id << std::endl;

    std::shared_ptr<CAConfig> ca = prof.getCA();

    if( !ca ) {
        signlog << "ERROR: Signing CA specified in profile could not be loaded." << std::endl;
        throw "CA-key not found";
    }

    signlog << "FINE: Key for Signing CA is correctly loaded." << std::endl;

    signlog << "INFO: Baseline Key Usage is: " << prof.ku << std::endl;
    signlog << "INFO: Extended Key Usage is: " << prof.eku << std::endl;

    signlog << "FINE: Signing is wanted by: " << cert->wishFrom << std::endl;
    signlog << "FINE: Signing is wanted for: " << cert->wishTo << std::endl;

    std::shared_ptr<X509Req> req;

    if( cert->csr_type == "SPKAC" ) {
        req = X509Req::parseSPKAC( cert->csr_content );
    } else if( cert->csr_type == "CSR" ) {
        req = X509Req::parseCSR( cert->csr_content );
    } else {
        signlog << "ERROR: Unknown type of certification in request: " << cert->csr_type << std::endl;
        throw "Error, unknown REQ rype " + ( cert->csr_type );
    }

    int i = req->verify();

    if( i < 0 ) {
        throw "Request contains a Signature with problems ... ";
    } else if( i == 0 ) {
        throw "Request contains a Signature that does not match ...";
    } else {
        signlog << "FINE: Request contains valid self-signature." << std::endl;
    }

    // Construct the Certificate
    X509Cert c = X509Cert();

    signlog << "INFO: Populating RDN ..." << std::endl;
    for( std::shared_ptr<AVA> a : cert->AVAs ) {
        signlog << "INFO: Trying to add RDN: " << a->name << ": " << a->value << std::endl;

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
            signlog << "ERROR: Trying to add illegal RDN/AVA type: " << a->name << std::endl;
            throw "Unhandled/Illegal AVA type";
        }
    }

    signlog << "INFO: Populating Issuer ..." << std::endl;
    c.setIssuerNameFrom( ca->ca );

    signlog << "INFO: Validating Public key for use in certificate" << std::endl;
    signlog << "INFO: - Checking generic key parameters" << std::endl;
    signlog << "FINE:   ->Public Key parameters are okay" << std::endl;

    signlog << "INFO: - Checking blacklists" << std::endl;
    signlog << "FINE:   ->Does not appear on any blacklist" << std::endl;

    signlog << "INFO: - Checking trivial factorization" << std::endl;
    signlog << "FINE:   ->Trivial factorization not possible" << std::endl;

    signlog << "INFO: - Checking astrological signs" << std::endl;
    signlog << "FINE:   ->The stars look good for this one" << std::endl;
    signlog << "FINE: Public key is fine for use in certificate" << std::endl;

    signlog << "INFO: Copying Public Key from Request ..." << std::endl;
    c.setPubkeyFrom( req );
    signlog << "FINE: Public Key successfully copied from Request." << std::endl;

    {
        signlog << "INFO: Determining Validity Period ..." << std::endl;
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

        if( ((from - now) > /* 2 Weeks */ (2 * 7 * 24 * 60 * 60)) || ((now - from) >= 0) ) {
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

        if( (to - from > limit) || (to - from < 0) ) {
            to = from + limit;
        }

        c.setTimes( from, to );
        signlog << "FINE: Setting validity period successful:" << std::endl;
        {
            struct tm* timeobj;
            std::vector<char> timebuf;

            timeobj = gmtime(&from);
            timebuf.resize(128);
            timebuf.resize(std::strftime(const_cast<char *>(timebuf.data()), timebuf.size(), "%F %T %Z", timeobj));
            signlog << "FINE: - Valid not before: " << std::string(timebuf.cbegin(), timebuf.cend()) << std::endl;

            timeobj = gmtime(&to);
            timebuf.resize(128);
            timebuf.resize(std::strftime(const_cast<char *>(timebuf.data()), timebuf.size(), "%F %T %Z", timeobj));
            signlog << "FINE: - Valid not after:  " << std::string(timebuf.cbegin(), timebuf.cend()) << std::endl;
        }
    }

    signlog << "INFO: Setting extensions:" << std::endl;
    c.setExtensions( ca->ca, cert->SANs, prof );
    signlog << "FINE: Setting extensions successful." << std::endl;

    signlog << "INFO: Generating next Serial Number ..." << std::endl;
    std::shared_ptr<BIGNUM> ser;
    std::string num;
    std::tie( ser, num ) = nextSerial( prof, ca );
    c.setSerialNumber( ser.get() );
    signlog << "FINE: Certificate Serial Number set to:" << num << std::endl;

    {
        signlog << "INFO: Trying to sign Certificate:" << std::endl;
        std::shared_ptr<SignedCertificate> output = c.sign( ca->caKey, cert->md );
        signlog << "INFO: Writing certificate to local file." << std::endl;
        std::string fn = writeBackFile( num, output->certificate, ca->path );

        if( fn.empty() ) {
            signlog << "ERROR: failed to get filename for storage of signed certificate." << std::endl;
            throw "Storage location could not be determined";
        }
        signlog << "FINE: Certificate signed successfully." << std::endl;
        signlog << "FINE: - Certificate written to: " << fn << std::endl;

        output->ca_name = ca->name;
        output->log = signlog.str();
        return output;
    }

}

std::pair<std::shared_ptr<CRL>, std::string> SimpleOpensslSigner::revoke( std::shared_ptr<CAConfig> ca, std::vector<std::string> serials ) {
    std::string crlpath = ca->path + "/ca.crl";

    std::shared_ptr<CRL> crl( new CRL( crlpath ) );
    std::string date = "";

    for( std::string serial : serials ) {
        date = crl->revoke( serial, "" );
    }

    crl->sign( ca );
    writeFile( crlpath, crl->toString() );
    return std::pair<std::shared_ptr<CRL>, std::string>( crl, date );
}
