#include "slipBio.h"

#include <iostream>

char hexDigit( char c ) {
    if( c < 0 ) {
        return 'x';
    }

    if( c < 10 ) {
        return '0' + c;
    }

    if( c < 16 ) {
        return 'A' + c - 10;
    }

    return 'x';
}

std::string toHex( const char* buf, int len ) {
    char* c = ( char* ) malloc( len * 2 );

    if( !c ) {
        return "<malloc fail>";
    }

    std::shared_ptr<char> mem = std::shared_ptr<char>( c, free );

    for( int i = 0; i < len; i++ ) {
        c[i * 2] = hexDigit( ( buf[i] >> 4 ) & 0xF );
        c[i * 2 + 1] = hexDigit( buf[i] & 0xF );
    }

    return std::string( mem.get(), len * 2 );
}

SlipBIO::SlipBIO( std::shared_ptr<OpensslBIO> target ) {
    this->target = target;

    this->buffer = std::vector<char>( 4096 );
    this->decodeTarget = 0;
    this->decodePos = 0;
    this->rawPos = 0;

    this->failed = false;
}

SlipBIO::~SlipBIO() {}

int SlipBIO::write( const char* buf, int num ) {
    int badOnes = 0;

    for( int i = 0; i < num; i++ ) {
        if( ( buf[i] == ( char )0xc0 ) || ( buf[i] == ( char )0xDB ) ) {
            badOnes++;
        }
    }

    int totalLen = num + badOnes + 2;
    char* targetPtr = ( char* ) malloc( totalLen );

    if( !targetPtr ) {
        return -1;
    }

    std::shared_ptr<char> t = std::shared_ptr<char>( targetPtr, free );
    int j = 0;
    targetPtr[j++] = ( char )0xC0;

    for( int i = 0; i < num; i++ ) {
        if( buf[i] == ( char )0xc0 ) {
            targetPtr[j++] = ( char )0xDB;
            targetPtr[j++] = ( char )0xDC;
        } else if( buf[i] == ( char )0xDB ) {
            targetPtr[j++] = ( char )0xDB;
            targetPtr[j++] = ( char )0xDD;
        } else {
            targetPtr[j++] = buf[i];
        }
    }

    targetPtr[j++] = ( char )0xC0;

    if( target->write( targetPtr, j ) != j ) {
        throw "Error, target write failed";
    }

    std::cout << toHex( targetPtr, j ) << std::endl;
    return num;
}

int SlipBIO::read( char* buf, int size ) {
    if( ( unsigned int ) size < buffer.capacity() ) {
        // fail...
    }

    // while we have no data to decode or unmasking does not yield a full package
    while( decodePos >= rawPos || !unmask() ) {

        // we have no data, read more
        if( buffer.size() - rawPos < 64 ) {
            // not enough space... package is too big
            decodeTarget = 0;
            failed = true;
        }

        int len = target->read( buffer.data() + rawPos, buffer.capacity() - rawPos );

        if( len > 0 ) {
            rawPos += len;
        } else {
            decodeTarget = 0;
            failed = true;
        }

    }

    // a package finished, return it
    std::copy( buffer.data(), buffer.data() + decodeTarget, buf );
    // move the buffer contents back

    int len = decodeTarget;
    decodeTarget = 0;

    return len;
}

long SlipBIO::ctrl( int cmod, long arg1, void* arg2 ) {
    ( void ) cmod;
    ( void ) arg1;
    ( void ) arg2;

    return 0;
}

const char* SlipBIO::getName() {
    return "SlipBIO";
}

bool SlipBIO::unmask() {
    unsigned int j = decodeTarget;

    for( unsigned int i = decodePos; i < rawPos; i++ ) {
        if( buffer[i] == ( char ) 0xDB ) {
            i++;

            if( i >= rawPos ) {
                decodeTarget = j;
                buffer[decodeTarget] = buffer[i - 1];
                decodePos = decodeTarget;
                rawPos = decodePos + 1;
                return 0;// no packet
            } else if( buffer[i] == ( char )0xdc ) {
                buffer[j++] = ( char ) 0xc0;
            } else if( buffer[i] == ( char )0xdd ) {
                buffer[j++] = ( char ) 0xdb;
            } else {
                decodeTarget = 0;
                failed = true;
                // failed package
                // error
            }
        } else if( buffer[i] == ( char ) 0xc0 ) {
            decodePos = i + 1;
            decodeTarget = j;

            // copy rest to bufferfer i to len
            if( !failed ) {
                return 1;
            }

            decodeTarget = 0;
            failed = false;
        } else {
            buffer[j++] = buffer[i];
        }
    }

    decodePos = j;
    rawPos = j;
    decodeTarget = j;

    return 0;
}
