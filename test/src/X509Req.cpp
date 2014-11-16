#include <iostream>

#include <boost/test/unit_test.hpp>

#include "X509.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE( TestX509Req )

BOOST_AUTO_TEST_CASE( CSR ) {
    // Testing a valid CSR
    std::shared_ptr<X509Req> req( X509Req::parseCSR( readFile( "testdata/test.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 1 );

    // Testing a CSR, where the signature content has been tampered with
    req = std::shared_ptr<X509Req>( X509Req::parseCSR( readFile( "testdata/test_false_sig.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() == 0 );

    // Testing a CSR, where the signature OID is something strange
    req = std::shared_ptr<X509Req>( X509Req::parseCSR( readFile( "testdata/test_invalid_sig.csr" ) ) );
    BOOST_REQUIRE( req );
    BOOST_CHECK( req->verify() < 0 );
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
