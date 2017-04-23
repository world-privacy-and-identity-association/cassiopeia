#pragma once

#include <memory>
#include <vector>

#include "io/bios.h"

class SlipBIO : public OpensslBIO {
private:
    std::shared_ptr<OpensslBIO> target;

    std::vector<char> buffer;

    std::vector<char> header = {0, 0, 0, 0, 0, 0, 0, 0};
    int resetCounter = -1; // -1 means waiting for start byte

    unsigned int decodeTarget;
    unsigned int decodePos;
    unsigned int rawPos;

    bool waitForConnection = true;
    bool waitForReset = false;
    bool packageLeft = false;

    bool server = false;

private:
    int unmask();

public:
    SlipBIO( std::shared_ptr<OpensslBIO> target );
    SlipBIO();
    ~SlipBIO();

    void setTarget( std::shared_ptr<OpensslBIO> target, bool server );

    virtual int write( const char *buf, int num );
    virtual int read( char *buf, int size );
    virtual long ctrl( int cmod, long arg1, void *arg2 );

    static const char *getName();
};
