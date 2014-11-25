#pragma once

#include "bios.h"

class OpensslBIOWrapper : public OpensslBIO {
private:
    BIO* b;
public:
    OpensslBIOWrapper( BIO* b );
    virtual ~OpensslBIOWrapper();

    int write( const char* buf, int num );
    int read( char* buf, int size );
    long ctrl( int cmod, long arg1, void* arg2 );

    int puts( const char* str );
    int gets( char* str, int size );

    static const char* getName();
};
