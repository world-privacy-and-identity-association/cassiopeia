#include "opensslBIO.h"

OpensslBIOWrapper::OpensslBIOWrapper( std::shared_ptr<BIO> b ) {
    this->b = b;
}

OpensslBIOWrapper::~OpensslBIOWrapper() {
}

int OpensslBIOWrapper::write( const char* buf, int num ) {
    return BIO_write( b.get(), buf, num );
}

int OpensslBIOWrapper::read( char* buf, int size ) {
    return BIO_read( b.get(), buf, size );
}

long OpensslBIOWrapper::ctrl( int cmod, long arg1, void* arg2 ) {
    return BIO_ctrl( b.get(), cmod, arg1, arg2 );
}

int OpensslBIOWrapper::puts( const char* str ) {
    return BIO_puts( b.get(), str );
}

int OpensslBIOWrapper::gets( char* str, int size ) {
    return BIO_gets( b.get(), str, size );
}

const char* OpensslBIOWrapper::getName() {
    return "OpenSSLWrapper";
}
