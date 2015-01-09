#include "CRL.h"

#include <openssl/ssl.h>

CRL::CRL( std::string path ) {
    std::shared_ptr<BIO> bio( BIO_new_file( path.c_str(), "r" ), free );
    crl = std::shared_ptr<X509_CRL>( PEM_read_bio_X509_CRL( bio.get(), 0, NULL, 0 ), X509_CRL_free );

    if( !crl ) {
        crl = std::shared_ptr<X509_CRL>( X509_CRL_new(), X509_CRL_free );
    }
}

std::string CRL::revoke( std::string serial, std::string time ) {
    BIGNUM* serBN = 0;

    if( ! BN_hex2bn( &serBN, serial.c_str() ) ) {
        throw "hex2bn malloc fail";
    }

    std::shared_ptr<BIGNUM> serBNP( serBN, BN_free );
    std::shared_ptr<ASN1_INTEGER> ser( BN_to_ASN1_INTEGER( serBN, NULL ), ASN1_INTEGER_free );

    if( !ser ) {
        throw "BN Malloc fail";
    }

    std::shared_ptr<ASN1_TIME> tmptm( ASN1_TIME_new(), ASN1_TIME_free );

    if( !tmptm ) {
        throw "ASN1-Time Malloc fail";
    }

    X509_gmtime_adj( tmptm.get(), 0 );

    X509_REVOKED* rev = X509_REVOKED_new();
    X509_REVOKED_set_serialNumber( rev, ser.get() );

    if( time != "" ) {
        const unsigned char* data = ( unsigned char* )( time.data() );
        d2i_ASN1_TIME( &rev->revocationDate, &data, time.size() );
    } else {
        X509_REVOKED_set_revocationDate( rev, tmptm.get() );
    }

    X509_CRL_add0_revoked( crl.get(), rev );

    int len = i2d_ASN1_TIME( tmptm.get(), NULL );
    unsigned char* buffer = ( unsigned char* ) OPENSSL_malloc( len );
    unsigned char* pos = buffer;
    i2d_ASN1_TIME( tmptm.get(), &pos );
    std::string rettime = std::string( ( char* ) buffer, len );
    OPENSSL_free( buffer );
    return rettime;
}

void CRL::sign( std::shared_ptr<CAConfig> ca ) {
    // Updating necessary CRL props
    std::shared_ptr<ASN1_TIME> tmptm( ASN1_TIME_new(), ASN1_TIME_free );

    if( !tmptm ) {
        throw "ASN1-Time Malloc fail";
    }

    X509_gmtime_adj( tmptm.get(), 0 );

    if( !X509_CRL_set_issuer_name( crl.get(), X509_get_subject_name( ca->ca.get() ) ) ) {
        throw "Setting issuer failed";
    }

    X509_CRL_set_lastUpdate( crl.get(), tmptm.get() );

    if( !X509_time_adj_ex( tmptm.get(), 1, 10, NULL ) ) {
        throw "Updating time failed";
    }

    X509_CRL_set_nextUpdate( crl.get(), tmptm.get() );

    // Sorting and signing
    X509_CRL_sort( crl.get() );
    X509_CRL_sign( crl.get(), ca->caKey.get(), EVP_sha256() );
}

bool CRL::verify( std::shared_ptr<CAConfig> ca ) {
    std::shared_ptr<EVP_PKEY> pk( X509_get_pubkey( ca->ca.get() ), EVP_PKEY_free );
    return X509_CRL_verify( crl.get(), pk.get() ) > 0;
}

std::string CRL::toString() {
    // Write out the new CRL
    std::shared_ptr<BIO> mem( BIO_new( BIO_s_mem() ), BIO_free );
    PEM_write_bio_X509_CRL( mem.get(), crl.get() );
    BUF_MEM* bptr;
    BIO_get_mem_ptr( mem.get(), &bptr );
    std::string newCRL( bptr->data, bptr->length );
    return newCRL;
}

std::string CRL::getSignature() {
    int len = i2d_X509_ALGOR( crl->sig_alg, NULL );
    len += i2d_ASN1_BIT_STRING( crl->signature, NULL );
    len += i2d_ASN1_TIME( crl->crl->lastUpdate, NULL );
    len += i2d_ASN1_TIME( crl->crl->nextUpdate, NULL );

    unsigned char* buffer = ( unsigned char* ) OPENSSL_malloc( len );
    unsigned char* pos = buffer;
    i2d_X509_ALGOR( crl->sig_alg, &pos );
    i2d_ASN1_BIT_STRING( crl->signature, &pos );
    i2d_ASN1_TIME( crl->crl->lastUpdate, &pos );
    i2d_ASN1_TIME( crl->crl->nextUpdate, &pos );
    std::string res = std::string( ( char* ) buffer, len );
    OPENSSL_free( buffer );

    return res;
}

void CRL::setSignature( std::string signature ) {
    const unsigned char* data = ( unsigned char* )( signature.data() );
    const unsigned char* buffer = data;
    d2i_X509_ALGOR( &crl->sig_alg, &buffer, signature.size() );
    d2i_ASN1_BIT_STRING( &crl->signature, &buffer, signature.size() + data - buffer );
    d2i_ASN1_TIME( &crl->crl->lastUpdate, &buffer, signature.size() + data - buffer );
    d2i_ASN1_TIME( &crl->crl->nextUpdate, &buffer, signature.size() + data - buffer );
}
