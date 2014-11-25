#pragma once

#include <openssl/bio.h>

#define BIO_TYPE_CUSTOM 0xff

class OpensslBIO {
public:
    static const int typeID = BIO_TYPE_CUSTOM;
    virtual ~OpensslBIO();

    virtual int write( const char* buf, int num ) = 0;
    virtual int read( char* buf, int size ) = 0;
    virtual int puts( const char* str );
    virtual int gets( char* str, int size );
    virtual long ctrl( int cmod, long arg1, void* arg2 ) = 0;
};

namespace BIOWrapper {

    int write( BIO* b, const char* buf, int num );
    int read( BIO* b, char* buf, int size );
    int puts( BIO* b, const char* str );
    int gets( BIO* b, char* str, int size );
    long ctrl( BIO* b, int cmod, long arg1, void* arg2 );

    template <typename T>
    int bio_new( BIO* b ) {
        b->init = 1;
        b->num = 0;
        b->ptr = new T();
        return 1;
    }

    int free( BIO* b );

}

template <typename T>
BIO_METHOD* toBio() {
    static BIO_METHOD new_method = {
        T::typeID,
        T::getName(),
        BIOWrapper::write,
        BIOWrapper::read,
        BIOWrapper::puts,
        BIOWrapper::gets,
        BIOWrapper::ctrl,
        BIOWrapper::bio_new<T>,
        BIOWrapper::free,
        NULL,
    };

    return &new_method;
}
