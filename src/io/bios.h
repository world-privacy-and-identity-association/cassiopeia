#pragma once

#include <openssl/bio.h>

struct bio_st {
  const BIO_METHOD *method;
  /* bio, mode, argp, argi, argl, ret */
  long (*callback) (struct bio_st *, int, const char *, int, long, long);
  char *cb_arg;               /* first argument for the callback */
  int init;
  int shutdown;
  int flags;                  /* extra storage */
  int retry_reason;
  int num;
  void *ptr;
  struct bio_st *next_bio;    /* used by filter BIOs */
  struct bio_st *prev_bio;    /* used by filter BIOs */
  int references;
  uint64_t num_read;
  uint64_t num_write;
  CRYPTO_EX_DATA ex_data;
  CRYPTO_RWLOCK *lock;
};


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
    return toBio<T>( BIOWrapper::bio_new<T> );
}

template <typename T>
BIO_METHOD* toBio( int ( *newfunc )( BIO* ) ) {
    BIO_METHOD *meth = BIO_meth_new( T::typeID, T::getName() );
    BIO_meth_set_write( meth, BIOWrapper::write );
    BIO_meth_set_read( meth, BIOWrapper::read );
    BIO_meth_set_puts( meth, BIOWrapper::puts );
    BIO_meth_set_gets( meth, BIOWrapper::gets );
    BIO_meth_set_ctrl( meth, BIOWrapper::ctrl );
    BIO_meth_set_destroy( meth, BIOWrapper::free );
    BIO_meth_set_create( meth, newfunc );

    return meth;
}
