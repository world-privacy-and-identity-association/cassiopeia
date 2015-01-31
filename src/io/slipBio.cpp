#include "slipBio.h"

#include <unistd.h>

#include <iostream>

#define BUFFER_SIZE 8192

#define SLIP_ESCAPE_CHAR ( (char) 0xDB)
#define SLIP_PACKET ( (char) 0xC0)

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
    std::string data = "000000";

    for( int i = 0; i < len; i++ ) {
        data.append( 1, ' ' );
        data.append( 1, hexDigit( ( buf[i] >> 4 ) & 0xF ) );
        data.append( 1, hexDigit( buf[i] & 0xF ) );
    }

    return data;
}

SlipBIO::SlipBIO() : buffer( std::vector<char>( BUFFER_SIZE ) ), decodeTarget( 0 ), decodePos( 0 ), rawPos( 0 ), failed( false ) {
}

void SlipBIO::setTarget( std::shared_ptr<OpensslBIO> target ) {
    this->target = target;
}

SlipBIO::SlipBIO( std::shared_ptr<OpensslBIO> target ) : target( target ), buffer( std::vector<char>( BUFFER_SIZE ) ), decodeTarget( 0 ), decodePos( 0 ), rawPos( 0 ), failed( false ) {
}

SlipBIO::~SlipBIO() {}

int SlipBIO::write( const char* buf, int num ) {
#ifdef SLIP_IO_DEBUG
    std::cout << "Out: " << toHex( buf, num ) << std::endl;
#endif

    int badOnes = 0;

    for( int i = 0; i < num; i++ ) {
        if( ( buf[i] == SLIP_PACKET ) || ( buf[i] == SLIP_ESCAPE_CHAR ) ) {
            badOnes++;
        }
    }

    int totalLen = num + badOnes + 1; // 2
    char* targetPtr = ( char* ) malloc( totalLen );

    if( !targetPtr ) {
        return -1;
    }

    std::shared_ptr<char> t = std::shared_ptr<char>( targetPtr, free );
    int j = 0;

    for( int i = 0; i < num; i++ ) {
        if( buf[i] == SLIP_PACKET ) {
            targetPtr[j++] = SLIP_ESCAPE_CHAR;
            targetPtr[j++] = ( char )0xDC;
        } else if( buf[i] == SLIP_ESCAPE_CHAR ) {
            targetPtr[j++] = SLIP_ESCAPE_CHAR;
            targetPtr[j++] = ( char )0xDD;
        } else {
            targetPtr[j++] = buf[i];
        }
    }

    targetPtr[j++] = SLIP_PACKET;
    int sent = 0;

    while( sent < j ) {

        errno = 0;
        int dlen = target->write( targetPtr + sent, std::min( 1024, j - sent ) );

        if( dlen < 0 ) {
            throw "Error, target write failed";
        } else if( dlen == 0 ) {
            // sleep
            usleep( 50000 );
        }

        if( errno != 0 ) {
            perror( "Error" );
        }

        sent += dlen;
    }

    return num;
}

int SlipBIO::read( char* buf, int size ) {
    // while we have no data to decode or unmasking does not yield a full package
    while( !packageLeft && ( decodePos >= rawPos || !unmask() ) ) {

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
            return -1;
            //decodeTarget = 0;
            //failed = true;
        }

    }

    packageLeft = true;
    int len = std::min( decodeTarget, ( unsigned int ) size );
    // a package finished, return it
    std::copy( buffer.data(), buffer.data() + len, buf );
    // move the buffer contents back
    std::copy( buffer.data() + len, buffer.data() + decodeTarget, buffer.data() );
    decodeTarget -= len;

    if( decodeTarget == 0 ) {
        packageLeft = false;
    }

#ifdef SLIP_IO_DEBUG
    std::cout << "in: " << toHex( buf, len ) << std::endl;
#endif

    return len;
}

long SlipBIO::ctrl( int cmod, long arg1, void* arg2 ) {
    ( void ) cmod;
    ( void ) arg1;
    ( void ) arg2;

    if( cmod == BIO_CTRL_RESET ) {
        char resetSequence[] = {SLIP_ESCAPE_CHAR, 0, SLIP_PACKET};
        target->write( resetSequence, 3 );
        decodePos = 0;
        decodeTarget = 0;
        rawPos = 0;
        std::cout << "resetting SLIP" << std::endl;
        return 0;
    }

    return target->ctrl( cmod, arg1, arg2 );
}

const char* SlipBIO::getName() {
    return "SlipBIO";
}

bool SlipBIO::unmask() {
    unsigned int j = decodeTarget;

    for( unsigned int i = decodePos; i < rawPos; i++ ) {
        if( buffer[i] == SLIP_ESCAPE_CHAR ) {
            i++;

            if( i >= rawPos ) {
                decodeTarget = j;
                buffer[decodeTarget] = buffer[i - 1];
                decodePos = decodeTarget;
                rawPos = decodePos + 1;
                return 0;// no packet
            } else if( buffer[i] == ( char )0xdc ) {
                buffer[j++] = SLIP_PACKET;
            } else if( buffer[i] == ( char )0xdd ) {
                buffer[j++] = SLIP_ESCAPE_CHAR;
            } else if( buffer[i] == SLIP_PACKET ) {
                failed = true;
                i--;
                continue;
            } else {
                decodeTarget = 0;
                failed = true;
                // failed package
                // error
            }
        } else if( buffer[i] == SLIP_PACKET ) {
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
