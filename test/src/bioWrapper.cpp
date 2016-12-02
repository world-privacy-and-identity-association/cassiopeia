#include <boost/test/unit_test.hpp>

#include "io/bios.h"
#include "io/opensslBIO.h"

class OpensslBIO1 : public OpensslBIO {
public:
    int state;

    int write( const char* buf, int num );
    int read( char* buf, int size );
    long ctrl( int cmod, long arg1, void* arg2 );

    static const char* getName();
};

int OpensslBIO1::write( const char* buf, int num ) {
    state = num * 2;
    ( void ) buf;
    return 0;
}

int OpensslBIO1::read( char* buf, int size ) {
    state = size * 3;
    ( void ) buf;
    return 0;
}

long OpensslBIO1::ctrl( int cmod, long arg1, void* arg2 ) {
    state = cmod * 7;
    ( void ) arg1;
    ( void ) arg2;
    return 0;
}

const char* OpensslBIO1::getName() {
    return "dummyBIO";
}

BOOST_AUTO_TEST_SUITE( TestBioWrapper )

BOOST_AUTO_TEST_CASE( BasicCalls ) {
    std::shared_ptr<BIO_METHOD> m(toBio<OpensslBIO1>(), BIO_meth_free);
    std::shared_ptr<BIO> n( BIO_new( m.get() ), BIO_free );
    OpensslBIO* o = new OpensslBIOWrapper( n );
    OpensslBIO1* data = ( OpensslBIO1* ) n->ptr;

    o->write( "bla", 13 );
    BOOST_CHECK( data->state == 13 * 2 );

    char buf[17];
    o->read( buf, 17 );
    BOOST_CHECK( data->state == 17 * 3 );

    o->ctrl( 19, 0, 0 );
    BOOST_CHECK( data->state == 19 * 7 );

    delete o;
}

BOOST_AUTO_TEST_SUITE_END()
