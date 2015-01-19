#include "util.h"

#include <boost/test/unit_test.hpp>
#include <iostream>
#include <openssl/err.h>


BOOST_AUTO_TEST_SUITE( TestTime )

BOOST_AUTO_TEST_CASE( testParseDate ) {
    if( 1 ) {
        return;
    }

    auto r = parseDate( "2012-01-01" );
    BOOST_CHECK( r.first );
    BOOST_CHECK( r.second == 1325376000 );

    r = parseDate( "1970-01-01" );
    BOOST_CHECK( r.first );
    BOOST_CHECK( r.second == 0 );

    BOOST_CHECK( !( parseDate( "" ) ).first );
    BOOST_CHECK( !( parseDate( "hallo" ) ).first );
    BOOST_CHECK( !( parseDate( "aaaa-aa-aa" ) ).first );
    BOOST_CHECK( !( parseDate( "32-12-12" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-13-01" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-00-01" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-02-30" ) ).first );
    BOOST_CHECK( ( parseDate( "2000-02-29" ) ).first );
    BOOST_CHECK( ( parseDate( "2000-01-31" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-01-32" ) ).first );
    BOOST_CHECK( !( parseDate( "2001-02-29" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-02-0" ) ).first );
    BOOST_CHECK( !( parseDate( "2000-02-99" ) ).first );
}

std::time_t extract( std::pair<bool, std::time_t> pair, std::string ex ) {
    BOOST_REQUIRE( pair.first );
    ( void ) ex;
    return pair.second;
}

#define CHECK_EQ(a, inter, b) BOOST_CHECK_EQUAL( extract(parseMonthInterval(extract(parseDate(a), "a"), inter),"b"), extract(parseDate(b),"c"))

#define CHECK_EQ_Y(a, inter, b) BOOST_CHECK_EQUAL( extract(parseYearInterval(extract(parseDate(a), "a"), inter),"b"), extract(parseDate(b),"c"))

BOOST_AUTO_TEST_CASE( testAddInverval ) {
    CHECK_EQ( "2000-01-01", "1m", "2000-02-01" );
    CHECK_EQ( "2000-02-29", "12m", "2001-02-28" );
    CHECK_EQ_Y( "2000-02-29", "1y", "2001-02-28" );
    CHECK_EQ( "1999-03-01", "12m", "2000-03-01" );
    CHECK_EQ_Y( "1999-03-01", "1y", "2000-03-01" );
    CHECK_EQ( "2000-01-29", "1m", "2000-02-29" );
    CHECK_EQ( "2001-01-29", "1m", "2001-02-28" );
    CHECK_EQ( "2100-01-29", "1m", "2100-02-28" );
    CHECK_EQ( "2400-01-29", "1m", "2400-02-29" );
    CHECK_EQ( "2099-11-30", "3m", "2100-02-28" );
    CHECK_EQ( "2399-07-29", "7m", "2400-02-29" );
}
BOOST_AUTO_TEST_CASE( testInvalidInverval ) {
    std::time_t base = 0;
    BOOST_CHECK( !( parseMonthInterval( base, "1" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "-m" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "0m" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "-1m" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "1g" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "12ym" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "12my" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "-2y2m" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "--2m" ).first ) );
    BOOST_CHECK( !( parseMonthInterval( base, "25m" ).first ) ); // too big

    BOOST_CHECK( !( parseYearInterval( base, "12my" ).first ) );
    BOOST_CHECK( !( parseYearInterval( base, "-2m2y" ).first ) );
    BOOST_CHECK( !( parseYearInterval( base, "--2y" ).first ) );
    BOOST_CHECK( !( parseYearInterval( base, "3y" ).first ) ); // too big

}

BOOST_AUTO_TEST_SUITE_END()
