#include "slipBio.h"

#include <unistd.h>

#include <iostream>

#include "log/logger.hpp"

static constexpr std::size_t buffer_size =  2 * 0xFFFF + 20;//8192;

#define SLIP_ESCAPE_CHAR ( (char) 0xDB)
#define SLIP_CONNECTION ( (char) 0xC0)
#define SLIP_RESET ( (char) 0xCB )

//#define SLIP_IO_DEBUG
//#define RAW_IO_DEBUG
//#define UNMASK_DEBUG

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

SlipBIO::SlipBIO() : buffer( buffer_size ), decodeTarget( 0 ), decodePos( 0 ), rawPos( 0 ) {
}

void SlipBIO::setTarget( std::shared_ptr<OpensslBIO> target, bool server ) {
    this->target = target;
    this->server = server;
}

SlipBIO::SlipBIO( std::shared_ptr<OpensslBIO> target ) : target( target ), buffer( std::vector<char>( buffer_size ) ), decodeTarget( 0 ), decodePos( 0 ), rawPos( 0 ) {
}

SlipBIO::~SlipBIO() {}

int SlipBIO::write( const char* buf, int num ) {
#ifdef SLIP_IO_DEBUG
    logger::notef( "slip-out: %s", toHex( buf, num ) );
#endif
    if( waitForReset ) {
        logger::note( "denying read because of reset-need!" );
        return -1;
    }


    int badOnes = 0;

    for( int i = 0; i < num; i++ ) {
        if( ( buf[i] == SLIP_CONNECTION ) || ( buf[i] == SLIP_ESCAPE_CHAR ) ) {
            badOnes++;
        }
    }

    int totalLen = num + badOnes; // 2
    char* targetPtr = ( char* ) malloc( totalLen );

    if( !targetPtr ) {
        return -1;
    }

    std::shared_ptr<char> t = std::shared_ptr<char>( targetPtr, free );
    int j = 0;

    for( int i = 0; i < num; i++ ) {
        if( buf[i] == SLIP_CONNECTION ) {
            targetPtr[j++] = SLIP_ESCAPE_CHAR;
            targetPtr[j++] = ( char )0xDC;
        } else if( buf[i] == SLIP_ESCAPE_CHAR ) {
            targetPtr[j++] = SLIP_ESCAPE_CHAR;
            targetPtr[j++] = ( char )0xDD;
        } else {
            targetPtr[j++] = buf[i];
        }
    }

    int sent = 0;

    while( sent < j ) {

        errno = 0;
        int dlen = target->write( targetPtr + sent, std::min( 1024, j - sent ) );
#ifdef RAW_IO_DEBUG
        std::ostringstream debug;
        debug << "Wrote " << dlen << " bytes: ";
        debug << toHex( targetPtr + sent, dlen );
        logger::note( debug.str() );
#endif

        if( dlen < 0 ) {
            throw "Error, target write failed";
        } else if( dlen == 0 ) {
            // sleep
            logger::note( "waiting for write ability" );
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
#ifdef UNMASK_DEBUG
    logger::note( "starting read" );
#endif
    // while we have no data to decode or unmasking does not yield a full package
    while( decodeTarget == 0 ) {
        if( waitForReset ) {
            logger::note( "denying read because of reset-need!" );
            return -1;
        }
        if(decodePos < rawPos) {
            int res = unmask();
            if( res == 1 ) {
                continue; // probably Packet :-)
            } else if(res == -1) {
                logger::note( "sending reset because of malfomed packet" );
               return -1;
            }
        }
        if( decodeTarget != 0 ){
            // we have data now, emit it!
            break;
        }
        // we have no data, read more
        if( buffer.size() - rawPos < 64 ) {
            // not enough space... package is too big
            decodeTarget = 0;
            waitForConnection = true;
            waitForReset = true;
            resetCounter = -1;
            return -1;
        }

#ifdef UNMASK_DEBUG
        logger::note( "beginning read" );
#endif
#ifdef RAW_IO_DEBUG
        std::ostringstream converter;
        converter << "rawPos is now: " << rawPos << ", buffer.size():" << buffer.size();
        logger::note( converter.str() );
#endif
        int len = target->read( buffer.data() + rawPos, buffer.size() - rawPos );
#ifdef RAW_IO_DEBUG
        logger::note( toHex(buffer.data() + rawPos, len ) );
#endif
        if( len > 0 ) {
            rawPos += len;
        } else {
            logger::note("Reporting EOS from slip");
            return -1;
            //decodeTarget = 0;
            //failed = true;
        }

    }
    if( waitForReset ) return -1;

    int len = std::min( decodeTarget, ( unsigned int ) size );
    // a package finished, return it
    std::copy( buffer.data(), buffer.data() + len, buf );
    // move the buffer contents back
    std::copy( buffer.data() + len, buffer.data() + decodeTarget, buffer.data() );
    decodeTarget -= len;
#ifdef UNMASK_DEBUG
    std::ostringstream convert;
    convert << "decodeTarget: " << decodeTarget << ", rawPos: " << rawPos << ", decodePos: " << decodePos;
    convert << ", requested were: " << size;
    logger::note( convert.str() );
#endif
    
    if(decodeTarget == 0 && rawPos <= decodePos + 1){
        // compact the remaining at most 1 byte of raw data
        buffer[0] = buffer[decodePos];
        rawPos -= decodePos;
        decodePos = 0;
    }

#ifdef SLIP_IO_DEBUG
    logger::notef( "slip-in: %s", toHex( buf, len ) );
#endif

    return len;
}

long SlipBIO::ctrl( int cmod, long arg1, void* arg2 ) {
    ( void ) cmod;
    ( void ) arg1;
    ( void ) arg2;

    if( cmod == BIO_CTRL_RESET ) {
        decodeTarget = 0;
        if( server ) {
            waitForReset = false;
            waitForConnection = true;
            resetCounter = -1;
        } else {
            static char ctr = 8;
            char resetSequence[] = {SLIP_CONNECTION, 1,2,3,4,5,6,7, ctr};
            target->write( resetSequence, 9 );
            header = {1, 2, 3, 4, 5, 6, 7, ctr};
            resetCounter = -1;
            waitForConnection = true;
            logger::note( "Resetting SLIP layer" );
        }
        return 0;
    }else if(cmod == BIO_CTRL_FLUSH ){
#ifdef UNMASK_DEBUG
        logger::note( "flush requested ");
#endif
    }

    return target->ctrl( cmod, arg1, arg2 );
}

const char* SlipBIO::getName() {
    return "SlipBIO";
}

// 1 success, data avail, 0 need moar data (see that decodeTarget is still 0),
// -1: fail... connection needs resetting
int SlipBIO::unmask() {
#ifdef UNMASK_DEBUG
    {
        std::ostringstream conv;
        conv << "unmasking starting, decodeTarget: " << decodeTarget << " decodePos: " << decodePos << " rawPos: " << rawPos << "bytes stored";
        logger::note( conv.str() );
    }
    logger::note( "unmasking" );
#endif
    if( waitForConnection ){
#ifdef UNMASK_DEBUG
        logger::note( "scanning for connection" );
#endif
        decodeTarget = 0;
        if( server ) {
#ifdef UNMASK_DEBUG
            logger::note( "on server site, waiting for CONNECTION-byte");
#endif
            while(decodePos < rawPos) {
                if(buffer[decodePos] == SLIP_CONNECTION) {
                    resetCounter = 0;
#ifdef UNMASK_DEBUG
                    logger::note( "got connection byte" );
#endif
                } else if(resetCounter >= 0) {
                    header[resetCounter] = buffer[decodePos];
                    resetCounter++;
                }
                decodePos++;
                if( resetCounter >= ((int) header.size()) ){
                    waitForConnection = false;
                    char data[] = { SLIP_CONNECTION };
                    target->write( data, 1);
#ifdef UNMASK_DEBUG
                    logger::notef( "SLIP, initing connection with ping-seq %s:", toHex(header.data(), header.size()) );
#endif
                    target->write( header.data(), header.size() );
                    break;
                }
            }
            if( decodePos >= rawPos ){
                decodePos = 0;
                rawPos = 0;
                return 0; // no package
            }
            
        } else {
            while(decodePos < rawPos) {
                if(buffer[decodePos] == SLIP_CONNECTION) {
#ifdef UNMASK_DEBUG
                    logger::note( "got connbyte" );
#endif
                    resetCounter = 0;
                } else if(resetCounter >= 0) {
#ifdef UNMASK_DEBUG
                    logger::note( "got head-byte" );
#endif
                    if(buffer[decodePos] == header[resetCounter]) {
                        resetCounter++;
                    } else {
                        resetCounter = -1;
                    }
                }
                decodePos++;
                if( resetCounter >= ((int) header.size()) ){
                    waitForConnection = false;
#ifdef UNMASK_DEBUG
                    logger::note("connection found! :-)!");
#endif
                    break;
                }
            }
            if( decodePos >= rawPos ){
                rawPos = 0;
                decodePos = 0;
                return 0; // no package
            }
        }
    }
    unsigned int j = decodeTarget;

    for( unsigned int i = decodePos; i < rawPos; i++ ) {
        if(waitForConnection && buffer[i] != SLIP_CONNECTION ) {
            continue;
        }
        if( buffer[i] == SLIP_ESCAPE_CHAR ) {
            i++;

            if( i >= rawPos ) {
                decodeTarget = j;
                buffer[decodeTarget] = buffer[i - 1];
                decodePos = decodeTarget;
                rawPos = decodePos + 1;
                return 0;// no packet
            } else if( buffer[i] == ( char )0xdc ) {
                buffer[j++] = SLIP_CONNECTION;
            } else if( buffer[i] == ( char )0xdd ) {
                buffer[j++] = SLIP_ESCAPE_CHAR;
            } else if( buffer[i] == SLIP_ESCAPE_CHAR
                       || buffer[i] == SLIP_CONNECTION ) {
                i--;
                continue;
            } else {
                waitForReset = true;
                resetCounter = -1;
                waitForConnection = true;
                decodeTarget = 0;
                decodePos = i + 1;
                // failed package
                // error
                return -1; // we don't have a pkg, set all appropriately to wait for a pkg start for next pkg.
            }
        } else if( buffer[i] == SLIP_CONNECTION ) {
            decodePos = i;
            decodeTarget = j;

            // copy rest to bufferfer i to len
            if( !waitForConnection ) {
                waitForReset = true;
                resetCounter = -1;
                waitForConnection = true;
                decodeTarget = 0;
                decodePos = i;
                logger::note( "error connection failed" );
                return -1;
            }
            logger::note( "got package border; slip re-validated SHOULD NEVER HAPPEN!!" );
            decodeTarget = 0;
            waitForConnection = false;
        } else {
            buffer[j++] = buffer[i];
        }
    }

#ifdef UNMASK_DEBUG
    std::ostringstream conv;
    conv << "unmasking paused, 0 remaining, " << j << "bytes stored";
    logger::note( conv.str() );
#endif
    decodePos = j;
    rawPos = j;
    decodeTarget = j;
    return decodeTarget > 0;
}
