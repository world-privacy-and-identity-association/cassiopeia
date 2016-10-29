#include "crypto/CRL.h"
#include "config.h"

#include <boost/test/unit_test.hpp>

#include <iostream>
#include <unordered_map>

extern std::unordered_map<std::string, std::shared_ptr<CAConfig>> CAs;

BOOST_AUTO_TEST_SUITE( TestCRL )
BOOST_AUTO_TEST_CASE( SeperateSignature ) {
    parseProfiles();
    std::shared_ptr<CAConfig> ca = CAs.at( "unassured_2015_2" );

    CRL c( "" );
    c.sign( ca );
    std::string oldsig = c.getSignature();
    BOOST_CHECK( c.verify( ca ) );
    std::string date = c.revoke( "1234", "" );
    BOOST_CHECK( !c.verify( ca ) );
    c.sign( ca );
    BOOST_CHECK( c.verify( ca ) );
    std::string newsig = c.getSignature();
    c.setSignature( oldsig );
    BOOST_CHECK( !c.verify( ca ) );
    c.setSignature( newsig );
    BOOST_CHECK( c.verify( ca ) );

    CRL c2( "" );
    c2.sign( ca );

    std::string date2 = c2.revoke( "1234", date );
    BOOST_CHECK_EQUAL( date, date2 );
    c2.setSignature( newsig );
    BOOST_CHECK( c2.verify( ca ) );

    BOOST_CHECK_EQUAL( c.toString(), c2.toString() );

}

BOOST_AUTO_TEST_SUITE_END()
