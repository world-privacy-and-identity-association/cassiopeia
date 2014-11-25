#include "opensslBIO.h"

OpensslBIOWrapper::OpensslBIOWrapper( BIO* b ) {
    this->b = b;
}

OpensslBIOWrapper::~OpensslBIOWrapper() {
    BIO_free( b );
}

int OpensslBIOWrapper::write( const char* buf, int num ) {
    return BIO_write( b, buf, num );
}

int OpensslBIOWrapper::read( char* buf, int size ) {
    return BIO_read( b, buf, size );
}

long OpensslBIOWrapper::ctrl( int cmod, long arg1, void* arg2 ) {
    return BIO_ctrl( b, cmod, arg1, arg2 );
}

int OpensslBIOWrapper::puts( const char* str ) {
    return BIO_puts( b, str );
}

int OpensslBIOWrapper::gets( char* str, int size ) {
    return BIO_gets( b, str, size );
}

const char* OpensslBIOWrapper::getName() {
    return "OpenSSLWrapper";
}
