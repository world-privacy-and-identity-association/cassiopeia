#pragma once

#include <memory>
#include "bios.h"
#include <vector>
#include <exception>

class OpensslBIOWrapper : public OpensslBIO {
private:
    std::shared_ptr<BIO> b;
    std::vector<char> buffer;
    int pos = 0;
public:
    OpensslBIOWrapper( std::shared_ptr<BIO> b );
    virtual ~OpensslBIOWrapper();

    int write( const char *buf, int num );
    int read( char *buf, int size );
    long ctrl( int cmod, long arg1, void *arg2 );

    int puts( const char *str );
    int gets( char *str, int size );

    static const char *getName();

    std::string readLine();
};

class eof_exception : public std::exception {
};
