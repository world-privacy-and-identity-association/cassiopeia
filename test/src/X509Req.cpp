#include <iostream>

#include <boost/test/unit_test.hpp>

#include <openssl/err.h>

#include "X509.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE( TestX509Req )

BOOST_AUTO_TEST_CASE( CSR ) {
    // Testing a valid CSR
    std::shared_ptr<X509Req> req( X509Req::parseCSR( readFile( "testdata/test.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 1 );
    BOOST_REQUIRE( ERR_peek_error() == 0 );

    // Testing a CSR, where the signature content has been tampered with
    req = std::shared_ptr<X509Req>( X509Req::parseCSR( readFile( "testdata/test_false_sig.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 0 );
    BOOST_REQUIRE( ERR_get_error() != 0 ); // RSA_padding_check_PKCS1_type_1:block type is not 01
    BOOST_REQUIRE( ERR_get_error() != 0 ); // RSA_EAY_PUBLIC_DECRYPT:padding check failed
    BOOST_REQUIRE( ERR_get_error() != 0 ); // ASN1_item_verify:EVP lib
    BOOST_REQUIRE( ERR_get_error() == 0 );

    // Testing a CSR, where the signature OID is something strange
    req = std::shared_ptr<X509Req>( X509Req::parseCSR( readFile( "testdata/test_invalid_sig.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() < 0 );
    BOOST_REQUIRE( ERR_get_error() != 0 ); // ASN1_item_verify:unknown signature algorithm
    BOOST_REQUIRE( ERR_get_error() == 0 );
}

BOOST_AUTO_TEST_CASE( SPKAC ) {
    // Testing a valid SPKAC
    std::shared_ptr<X509Req> req( X509Req::parseSPKAC( readFile( "testdata/test.spkac" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 1 );

    // Testing a SPKAC, where the signature content has been tampered with
    req = std::shared_ptr<X509Req>( X509Req::parseSPKAC( readFile( "testdata/test_false_sig.spkac" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 0 );

    // Testing a SPKAC, where the signature OID is something strange
    req = std::shared_ptr<X509Req>( X509Req::parseSPKAC( readFile( "testdata/test_invalid_sig.spkac" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() < 0 );
}

BOOST_AUTO_TEST_SUITE_END()
