#pragma once

#include <memory>
#include <vector>

#include "bios.h"

class SlipBIO : public OpensslBIO {
private:
    std::shared_ptr<OpensslBIO> target;

    std::vector<char> buffer;

    unsigned int decodeTarget;
    unsigned int decodePos;
    unsigned int rawPos;

    bool failed;

private:
    bool unmask();

public:
    SlipBIO( std::shared_ptr<OpensslBIO> target );
    ~SlipBIO();

    virtual int write( const char* buf, int num );
    virtual int read( char* buf, int size );
    virtual long ctrl( int cmod, long arg1, void* arg2 );

    static const char* getName();
};
