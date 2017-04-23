#include "CRL.h"

#include <openssl/ssl.h>
#include <log/logger.hpp>
#include <exception>

CRL::CRL( std::string path ) {
    std::shared_ptr<BIO> bio( BIO_new_file( path.c_str(), "r" ), BIO_free );
    crl = std::shared_ptr<X509_CRL>( PEM_read_bio_X509_CRL( bio.get(), 0, NULL, 0 ), X509_CRL_free );

    if( !crl ) {
        crl = std::shared_ptr<X509_CRL>( X509_CRL_new(), X509_CRL_free );
    }
}

std::string CRL::revoke( std::string serial, std::string time ) {
    BIGNUM *serBN = 0;

    logger::note( "parsing serial" );

    if( ! BN_hex2bn( &serBN, serial.c_str() ) ) {
        throw std::runtime_error( "hex2bn malloc fail" );
    }

    std::shared_ptr<BIGNUM> serBNP( serBN, BN_free );
    std::shared_ptr<ASN1_INTEGER> ser( BN_to_ASN1_INTEGER( serBN, NULL ), ASN1_INTEGER_free );

    if( !ser ) {
        throw std::runtime_error( "BN Malloc fail" );
    }

    logger::note( "building current time" );
    std::shared_ptr<ASN1_TIME> tmptm( ASN1_TIME_new(), ASN1_TIME_free );

    if( !tmptm ) {
        throw std::runtime_error( "ASN1-Time Malloc fail" );
    }

    X509_gmtime_adj( tmptm.get(), 0 );

    logger::note( "creating entry" );
    X509_REVOKED *rev = X509_REVOKED_new();
    X509_REVOKED_set_serialNumber( rev, ser.get() );

    if( time != "" ) {
        ASN1_TIME_set_string( tmptm.get(), time.data() );
    }

    X509_REVOKED_set_revocationDate( rev, tmptm.get() );

    X509_CRL_add0_revoked( crl.get(), rev );

    int len = i2d_ASN1_TIME( tmptm.get(), NULL );
    unsigned char *buffer = ( unsigned char * ) OPENSSL_malloc( len );
    unsigned char *pos = buffer;
    i2d_ASN1_TIME( tmptm.get(), &pos );
    std::string rettime = std::string( ( char * ) buffer, len );
    OPENSSL_free( buffer );
    return rettime;
}

void CRL::sign( std::shared_ptr<CAConfig> ca ) {
    if( !ca->caKey ) {
        throw new std::invalid_argument( "Cannot sign CRL with CA " + ca->name + " because it has no private key." );
    }

    // Updating necessary CRL props
    std::shared_ptr<ASN1_TIME> tmptm( ASN1_TIME_new(), ASN1_TIME_free );

    if( !tmptm ) {
        throw std::runtime_error( "ASN1-Time Malloc fail" );
    }

    X509_gmtime_adj( tmptm.get(), 0 );

    logger::note( "setting issuer" );

    if( !X509_CRL_set_issuer_name( crl.get(), X509_get_subject_name( ca->ca.get() ) ) ) {
        throw std::runtime_error( "Setting issuer failed" );
    }

    logger::note( "setting update" );
    X509_CRL_set_lastUpdate( crl.get(), tmptm.get() );

    if( !X509_time_adj_ex( tmptm.get(), 1, 10, NULL ) ) {
        throw std::runtime_error( "Updating time failed" );
    }

    logger::note( "setting next update" );
    X509_CRL_set_nextUpdate( crl.get(), tmptm.get() );

    logger::note( "sorting" );
    // Sorting and signing
    X509_CRL_sort( crl.get() );
    logger::note( "signing" );
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
    BUF_MEM *bptr;
    BIO_get_mem_ptr( mem.get(), &bptr );
    std::string newCRL( bptr->data, bptr->length );
    return newCRL;
}

std::string CRL::getSignature() {
    const X509_ALGOR *palg;
    const ASN1_BIT_STRING *psig;

    X509_CRL_get0_signature( crl.get(), &psig, &palg );
    int len = i2d_X509_ALGOR( const_cast<X509_ALGOR *>( palg ), NULL );
    len += i2d_ASN1_BIT_STRING( const_cast<ASN1_BIT_STRING *>( psig ), NULL );
    len += i2d_ASN1_TIME( const_cast<ASN1_TIME *>( X509_CRL_get0_lastUpdate( crl.get() ) ), NULL );
    len += i2d_ASN1_TIME( const_cast<ASN1_TIME *>( X509_CRL_get0_nextUpdate( crl.get() ) ), NULL );

    unsigned char *buffer = ( unsigned char * ) OPENSSL_malloc( len );
    unsigned char *pos = buffer;
    i2d_X509_ALGOR( const_cast<X509_ALGOR *>( palg ), &pos );
    i2d_ASN1_BIT_STRING( const_cast<ASN1_BIT_STRING *>( psig ), &pos );
    i2d_ASN1_TIME( const_cast<ASN1_TIME *>( X509_CRL_get0_lastUpdate( crl.get() ) ), &pos );
    i2d_ASN1_TIME( const_cast<ASN1_TIME *>( X509_CRL_get0_nextUpdate( crl.get() ) ), &pos );
    std::string res = std::string( ( char * ) buffer, len );
    OPENSSL_free( buffer );

    return res;
}

void CRL::setSignature( std::string signature ) {
    X509_CRL_sort( crl.get() );
    X509_ALGOR *palg;
    ASN1_BIT_STRING *psig;
    // this is not intended use of the OPENSSL-API but API-limitations leave us with no other options.
    X509_CRL_get0_signature( crl.get(), const_cast<const ASN1_BIT_STRING **>( &psig ), const_cast<const X509_ALGOR **>( &palg ) );

    const unsigned char *data = ( unsigned char * )( signature.data() );
    const unsigned char *buffer = data;
    X509_ALGOR *alg = d2i_X509_ALGOR( NULL, &buffer, signature.size() );
    ASN1_BIT_STRING *sig = d2i_ASN1_BIT_STRING( NULL, &buffer, signature.size() + data - buffer );
    ASN1_TIME *a1 = d2i_ASN1_TIME( NULL, &buffer, signature.size() + data - buffer );
    ASN1_TIME *a2 = d2i_ASN1_TIME( NULL, &buffer, signature.size() + data - buffer );
    std::swap( *palg, *alg );
    std::swap( *psig, *sig );
    X509_CRL_set1_lastUpdate( crl.get(), a1 );
    X509_CRL_set1_nextUpdate( crl.get(), a2 );

    X509_ALGOR_free( alg );
    ASN1_BIT_STRING_free( sig );
    ASN1_TIME_free( a1 );
    ASN1_TIME_free( a2 );
}

bool CRL::needsResign() {
    time_t current;
    time( &current );
    current += 60 * 60;// 1 hour
    auto time = X509_CRL_get0_nextUpdate( crl.get() );

    if( !time ) {
        return true;
    }

    int cmp =  X509_cmp_time( time, &current );
    return cmp < 0;
}
