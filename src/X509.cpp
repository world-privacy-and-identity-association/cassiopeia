#include "X509.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

X509Req::X509Req( X509_REQ* csr ) {
    req = std::shared_ptr<X509_REQ>( csr, X509_REQ_free );
    EVP_PKEY* pkt = X509_REQ_get_pubkey( req.get() );

    if( !pkt ) {
        throw "Error extracting public key";
    }

    pk = std::shared_ptr<EVP_PKEY>( pkt, EVP_PKEY_free );
}

int X509Req::verify() {
    return X509_REQ_verify( req.get(), pk.get() );
}

std::shared_ptr<EVP_PKEY> X509Req::getPkey() {
    return pk;
}

std::shared_ptr<X509Req> X509Req::parse( std::string filename ) {
    std::shared_ptr<BIO> in = std::shared_ptr<BIO>( BIO_new_mem_buf( const_cast<char*>( filename.c_str() ), -1 ), BIO_free );
    X509_REQ* req = PEM_read_bio_X509_REQ( in.get(), NULL, NULL, NULL );

    if( !req ) {
        throw "Error parsing CSR";
    }

    return std::shared_ptr<X509Req>( new X509Req( req ) );
}

int add_ext( std::shared_ptr<X509> issuer, std::shared_ptr<X509> subj, int nid, const char* value ) {
    X509_EXTENSION* ex;
    X509V3_CTX ctx;

    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb( &ctx );

    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx( &ctx, issuer.get(), subj.get(), NULL, NULL, 0 );
    ex = X509V3_EXT_conf_nid( NULL, &ctx, nid, const_cast<char*>( value ) );

    if( !ex ) {
        return 0;
    }

    X509_add_ext( subj.get(), ex, -1 );
    X509_EXTENSION_free( ex );

    return 1;
}

X509Cert::X509Cert() {
    X509* c = X509_new();

    if( !c ) {
        throw "malloc failed";
    }

    target = std::shared_ptr<X509>( c, X509_free );

    if( !X509_set_version( c, 2 ) ) {
        throw "Setting X509-version to 3 failed";
    }
}

void X509Cert::setIssuerNameFrom( std::shared_ptr<X509> caCert ) {
    if( !X509_set_issuer_name( target.get(), X509_get_subject_name( caCert.get() ) ) ) {
        throw "Error setting Issuer name";
    }
}

void X509Cert::setPubkeyFrom( std::shared_ptr<X509Req> req ) {
    std::shared_ptr<EVP_PKEY> pktmp = req->getPkey();

    if( !X509_set_pubkey( target.get(), pktmp.get() ) ) {
        throw "Setting public key failed.";
    }
}

void X509Cert::setSerialNumber( int num ) {
    ASN1_INTEGER_set( target.get()->cert_info->serialNumber, num );
}

void X509Cert::setTimes( long before, long after ) {
    X509_gmtime_adj( X509_get_notBefore( target.get() ), before );
    X509_gmtime_adj( X509_get_notAfter( target.get() ), after );
}

void X509Cert::setExtensions( std::shared_ptr<X509> caCert ) {
    add_ext( caCert, target, NID_basic_constraints, "critical,CA:FALSE" );
    add_ext( caCert, target, NID_subject_key_identifier, "hash" );
    add_ext( caCert, target, NID_authority_key_identifier, "keyid,issuer:always" );
    add_ext( caCert, target, NID_key_usage, "critical,nonRepudiation,digitalSignature,keyEncipherment" );
    add_ext( caCert, target, NID_ext_key_usage, "clientAuth, serverAuth" );
    add_ext( caCert, target, NID_info_access, "OCSP;URI:http://ocsp.cacert.org" );
    add_ext( caCert, target, NID_crl_distribution_points, "URI:http://crl.cacert.org/class3-revoke.crl" );
}

std::string X509Cert::sign( std::shared_ptr<EVP_PKEY> caKey ) {
    if( !X509_sign( target.get(), caKey.get(), EVP_sha512() ) ) {
        throw "Signing failed.";
    }

    X509_print_fp( stdout, target.get() );
    std::shared_ptr<BIO> mem = std::shared_ptr<BIO>( BIO_new( BIO_s_mem() ), BIO_free );
    PEM_write_bio_X509( mem.get(), target.get() );
    BUF_MEM* buf;
    BIO_get_mem_ptr( mem.get(), &buf );
    std::string output( buf->data, buf->data + buf->length );
    return output;
}
