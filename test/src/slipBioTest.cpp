#include <iostream>
#include <cstring>

#include <boost/test/unit_test.hpp>

#include "bios.h"
#include "slipBio.h"

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
}

BOOST_AUTO_TEST_SUITE_END()
