#include "simpleOpensslSigner.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

std::shared_ptr<int> SimpleOpensslSigner::lib_ref(
    new int( SSL_library_init() ),
    []( int* ref ) {
        ( void ) ref;
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

std::shared_ptr<X509> SimpleOpensslSigner::caCert = loadX509FromFile( "assured.crt" );

std::shared_ptr<EVP_PKEY> SimpleOpensslSigner::caKey = loadPkeyFromFile( "assured.key" );

int add_ext( std::shared_ptr<X509> issuer, X509* subj, int nid, const char* value ) {
    X509_EXTENSION* ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb( &ctx );
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx( &ctx, issuer.get(), subj, NULL, NULL, 0 );
    ex = X509V3_EXT_conf_nid( NULL, &ctx, nid, const_cast<char*>( value ) );

    if( !ex ) {
        return 0;
    }

    X509_add_ext( subj, ex, -1 );
    X509_EXTENSION_free( ex );
    return 1;
}

void SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    if( !caKey ) {
        throw "CA-key not found";
    }

    std::shared_ptr<BIO> in = std::shared_ptr<BIO>(
        BIO_new_mem_buf( const_cast<char*>( cert->csr_content.c_str() ), -1 ),
        []( BIO * ref ) {
            BIO_free( ref );
        } );
    std::shared_ptr<X509_REQ> req = std::shared_ptr<X509_REQ>(
        PEM_read_bio_X509_REQ( in.get(), NULL, NULL, NULL ),
        []( X509_REQ * ref ) {
            if( ref ) {
                X509_REQ_free( ref );
            }
        } );

    if( !req ) {
        throw "Error parsing CSR";
    }

    EVP_PKEY* pktmp = X509_REQ_get_pubkey( req.get() );

    if( !pktmp ) {
        throw "Error extracting pubkey";
    }

    EVP_PKEY_free( pktmp );

    int i = X509_REQ_verify( req.get(), pktmp );

    if( i < 0 ) {
        throw "Signature problems ... ";
    } else if( i == 0 ) {
        throw "Signature did not match";
    } else {
        std::cerr << "Signature ok" << std::endl;
    }

    // Construct the Certificate

    std::shared_ptr<X509> ret = std::shared_ptr<X509>( X509_new(), X509_free );

    if( !ret ) {
        throw "Creating X509 failed.";
    }

    X509_CINF* ci = ret->cert_info;

    if( !X509_set_version( ret.get(), 2 ) ) {
        throw "Setting X509-version to 3 failed";
    }

    if( !X509_set_issuer_name( ret.get(), X509_get_subject_name( caCert.get() ) ) ) {
        throw "Error setting Issuer name";
    }

    // Serial and Pubkey
    ASN1_INTEGER_set( ci->serialNumber, 4711 );
    pktmp = X509_REQ_get_pubkey( req.get() );

    if( !X509_set_pubkey( ret.get(), pktmp ) ) {
        EVP_PKEY_free( pktmp );
        throw "Setting public key failed.";
    } else {
        EVP_PKEY_free( pktmp );
    }

    // Dates
    X509_gmtime_adj( X509_get_notBefore( ret.get() ), 0 );
    X509_gmtime_adj( X509_get_notAfter( ret.get() ), ( long )60 * 60 * 24 * 10 );

    // Extensions
    add_ext( caCert, ret.get(), NID_basic_constraints, "critical,CA:FALSE" );
    add_ext( caCert, ret.get(), NID_subject_key_identifier, "hash" );
    add_ext( caCert, ret.get(), NID_authority_key_identifier, "keyid,issuer:always" );
    add_ext( caCert, ret.get(), NID_key_usage, "critical,nonRepudiation,digitalSignature,keyEncipherment" );
    add_ext( caCert, ret.get(), NID_ext_key_usage, "clientAuth, serverAut" );
    add_ext( caCert, ret.get(), NID_info_access, "OCSP;URI:http://ocsp.cacert.org" );
    add_ext( caCert, ret.get(), NID_crl_distribution_points, "URI:http://crl.cacert.org/class3-revoke.crl" );

    if( !X509_sign( ret.get(), caKey.get(), EVP_sha512() ) ) {
        throw "Signing failed.";
    }

    X509_print_fp( stdout, ret.get() );
    std::shared_ptr<BIO> mem = std::shared_ptr<BIO>( BIO_new( BIO_s_mem() ), BIO_free );
    PEM_write_bio_X509( mem.get(), ret.get() );
    BUF_MEM* buf;
    BIO_get_mem_ptr( mem.get(), &buf );
    std::string output( buf->data, buf->data + buf->length );
    std::cout << "Certificate:" << std::endl << output << std::endl;
}
