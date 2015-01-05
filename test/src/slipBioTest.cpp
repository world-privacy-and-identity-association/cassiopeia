#include <iostream>
#include <cstring>

#include <boost/test/unit_test.hpp>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "io/bios.h"
#include "io/opensslBIO.h"
#include "io/slipBio.h"

class OpensslBIOVector : public OpensslBIO {
private:
    std::vector<std::vector<char>>::iterator it, end;
    std::vector<std::vector<char>> input;

public:
    std::vector<std::vector<char>> result = std::vector<std::vector<char>>();
    OpensslBIOVector( std::vector<std::vector<char>> data ) {
        input = data;
        it = input.begin();
        end = input.end();
    }

    int write( const char* buf, int num );
    int read( char* buf, int size );
    long ctrl( int cmod, long arg1, void* arg2 );

    static const char* getName();
};

int OpensslBIOVector::write( const char* buf, int num ) {
    result.push_back( std::vector<char>( buf, buf + num ) );
    return num;
}

int OpensslBIOVector::read( char* buf, int size ) {
    if( it == end ) {
        return -1;
    }

    if( ( unsigned int ) size < it->size() ) {
        throw "Error, to small buffer";
    }

    std::copy( it->begin(), it->end(), buf );
    auto result = it->size();
    it++;
    return result;
}

long OpensslBIOVector::ctrl( int cmod, long arg1, void* arg2 ) {
    ( void ) cmod;
    ( void ) arg1;
    ( void ) arg2;
    return 0;
}

const char* OpensslBIOVector::getName() {
    return "dummyBIO";
}

BOOST_AUTO_TEST_SUITE( TestSLIPBioWrapper )

BOOST_AUTO_TEST_CASE( TestMockup ) {
    std::vector<std::vector<char>> source = {{1, 2}, {1, 2, 3}, {1, 2, 3, 4}, {1, 2, 3, 4, 5}};

    OpensslBIOVector* data = new OpensslBIOVector( source );

    char buf[4096];

    for( auto it = source.begin(); it != source.end(); it++ ) {
        auto len = data->read( buf, sizeof( buf ) );
        BOOST_CHECK_EQUAL( len, it->size() );
        BOOST_CHECK_EQUAL_COLLECTIONS( buf, buf + len, it->begin(), it->end() );
        BOOST_CHECK_EQUAL( data->write( buf, len ), len );
    }

    BOOST_CHECK_EQUAL( data->read( buf, sizeof( buf ) ), -1 );

    for( unsigned int i = 0; i < source.size(); i++ ) {
        BOOST_CHECK_EQUAL_COLLECTIONS( data->result[i].begin(), data->result[i].end(), source[i].begin(), source[i].end() );
    }

    delete data;
}

BOOST_AUTO_TEST_CASE( TestSLIP ) {
    std::vector<std::vector<char>> source = { {1, 2, 3, 4, 5, ( char ) 0xc0, 1, ( char ) 0xc0}, {1, 2}, {( char ) 0xc0}, {1, ( char ) 0xdb}, {( char ) 0xdc}, {( char ) 0xc0, ( char )0xdb}, {( char ) 0xdd, 2}, {( char ) 0xc0}};
    std::shared_ptr<OpensslBIOVector> data = std::shared_ptr<OpensslBIOVector>( new OpensslBIOVector( source ) );
    char buf[4096];
    SlipBIO* slip = new SlipBIO( data );
    int res = slip->read( buf, sizeof( buf ) );
    BOOST_CHECK_EQUAL( res, 5 );
    res = slip->read( buf, sizeof( buf ) );
    BOOST_CHECK_EQUAL( res, 1 );
    res = slip->read( buf, sizeof( buf ) );
    BOOST_CHECK_EQUAL( res, 2 );

    res = slip->read( buf, sizeof( buf ) );
    BOOST_CHECK_EQUAL( res, 2 );
    char res2[] = {1, ( char ) 0xc0};
    BOOST_CHECK_EQUAL_COLLECTIONS( buf, buf + 2, res2, res2 + 2 );

    res = slip->read( buf, sizeof( buf ) );
    BOOST_CHECK_EQUAL( res, 2 );
    char res3[] = {( char ) 0xdb, 2};
    BOOST_CHECK_EQUAL_COLLECTIONS( buf, buf + 2, res3, res3 + 2 );
    delete slip;
}

BOOST_AUTO_TEST_CASE( TestSSLThroughSLIP ) {
    BIO* bio1, *bio2;
    BOOST_REQUIRE_EQUAL( BIO_new_bio_pair( &bio1, 8096, &bio2, 8096 ), 1 );
    BIO* slip1 = BIO_new( toBio<SlipBIO>() );
    ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( std::shared_ptr<BIO>( bio1, BIO_free ) ) ) );
    BIO* slip2 = BIO_new( toBio<SlipBIO>() );
    ( ( SlipBIO* )slip2->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( std::shared_ptr<BIO>( bio2, BIO_free ) ) ) );

    auto meth = TLSv1_method();
    auto c_ctx = SSL_CTX_new( meth );
    auto s_ctx = SSL_CTX_new( meth );
    //SSL_CTX_set_cipher_list(c_ctx, "ALL");
    //SSL_CTX_set_cipher_list(s_ctx, "ALL");
    SSL_CTX_use_certificate_file( s_ctx, "testdata/server.crt", SSL_FILETYPE_PEM );
    SSL_CTX_use_PrivateKey_file( s_ctx, "testdata/server.key", SSL_FILETYPE_PEM );
    auto c_ssl = SSL_new( c_ctx );
    auto s_ssl = SSL_new( s_ctx );
    auto c_bio = BIO_new( BIO_f_ssl() );
    auto s_bio = BIO_new( BIO_f_ssl() );
    SSL_set_connect_state( c_ssl );
    SSL_set_bio( c_ssl, slip1, slip1 );
    BIO_set_ssl( c_bio, c_ssl, BIO_NOCLOSE );

    SSL_set_accept_state( s_ssl );
    SSL_set_bio( s_ssl, slip2, slip2 );
    BIO_set_ssl( s_bio, s_ssl, BIO_NOCLOSE );

    char data[] = {1, 2, 3, 4, 5};
    char data2[5];
    //ERR_load_SSL_strings();
    //ERR_load_crypto_strings();

    int res = BIO_write( c_bio, data, 5 );
    BOOST_CHECK_EQUAL( res, -1 );
    res = BIO_read( s_bio, data2, sizeof( data2 ) );
    BOOST_CHECK_EQUAL( res, -1 );

    res = BIO_write( c_bio, data, 5 );
    BOOST_CHECK_EQUAL( res, -1 );

    res = BIO_read( s_bio, data2, sizeof( data2 ) );
    BOOST_CHECK_EQUAL( res, -1 );
    res = BIO_write( c_bio, data, 5 );
    BOOST_CHECK_EQUAL( res, 5 );
    res = BIO_read( s_bio, data2, sizeof( data2 ) );
    BOOST_CHECK_EQUAL( res, 5 );
    BOOST_CHECK_EQUAL_COLLECTIONS( data, data + 5, data2, data2 + 5 );

    BIO_free( c_bio );
    BIO_free( s_bio );

    BIO_free( slip1 );
    BIO_free( slip2 );
    SSL_free( c_ssl );
    SSL_free( s_ssl );

    SSL_CTX_free( c_ctx );
    SSL_CTX_free( s_ctx );
}

BOOST_AUTO_TEST_SUITE_END()
