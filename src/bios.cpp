#include "bios.h"

#include <string.h>

namespace BIOWrapper {

    int write( BIO* b, const char* buf, int num ) {
        return ( ( OpensslBIO* )b->ptr )->write( buf, num );
    }

    int read( BIO* b, char* buf, int size ) {
        return ( ( OpensslBIO* )b->ptr )->read( buf, size );
    }

    int puts( BIO* b, const char* str ) {
        return ( ( OpensslBIO* )b->ptr )->puts( str );
    }

    int gets( BIO* b, char* str, int size ) {
        return ( ( OpensslBIO* )b->ptr )->gets( str, size );
    }

    long ctrl( BIO* b, int cmod, long arg1, void* arg2 ) {
        return ( ( OpensslBIO* )b->ptr )->ctrl( cmod, arg1, arg2 );
    }

    int free( BIO* b ) {
        delete( ( OpensslBIO* ) b->ptr );
        b->ptr = 0;
        return 0;
    }

}

OpensslBIO::~OpensslBIO() {}

int OpensslBIO::puts( const char* str ) {
    ( void ) str;
    return -1;
}
int OpensslBIO::gets( char* str, int size ) {
    ( void ) str;
    ( void ) size;
    return -1;
}
