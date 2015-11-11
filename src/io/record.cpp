#include "record.h"

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "io/bios.h"
#include "io/opensslBIO.h"
#include "log/logger.hpp"

std::string toHexAndChecksum( const std::string& src ) {
    char checksum = 0;
    std::stringstream ss;
    ss << ':' << std::hex << std::setfill( '0' ) << std::uppercase;

    for( auto c : src ) {
        ss << std::setw( 2 ) << ( ( ( uint32_t ) c ) & 0xFF );
        checksum += c;
    }

    ss << std::setw( 2 ) << ( ( ( uint32_t )( ~checksum ) ) & 0xFF );
    ss << '\n';
    return ss.str();
}

void sendCommand( RecordHeader& head, const std::string& data, std::shared_ptr<OpensslBIO> bio ) {
    std::stringstream ss;
    ss << data.size();
    logger::debugf( "Record payload length: %s", ss.str() ); 
    if(data.size() > 0xFFFF){
        logger::warn( "Data too big, need chunking" );
    }
    head.payloadLength = data.size();
    std::string s;
    s += head.packToString();
    s += data;

    std::string res = toHexAndChecksum( s );

    logger::debug( "FINE: RECORD output: ", res );

    bio->write( res.data(), res.size() );
}

int32_t fromHexDigit( char c ) {
    int32_t res = -1;

    if( c >= '0' && c <= '9' ) {
        res = c - '0';
    }

    if( c >= 'A' && c <= 'F' ) {
        res = c - 'A' + 10;
    }

    return res;
}

std::string parseCommand( RecordHeader& head, const std::string& input) {
    logger::debug( "FINE: RECORD input: ", input );

    int32_t dlen = ( input.size() - 2 ) / 2;
    char checksum = 0;
    bool error = false;

    std::string str( std::max( dlen, RECORD_HEADER_SIZE ), 0 );

    for( int i = 0; i < dlen; i++ ) {
        int32_t digit;
        int32_t accum;
        digit = fromHexDigit( input[i * 2 + 1] );
        error |= digit == -1;
        accum = digit;
        accum <<= 4;
        digit = fromHexDigit( input[i * 2 + 2] );
        error |= digit == -1;
        accum += digit;
        str[i] = accum;
        checksum += str[i];
    }

    head.unpackFromString( str.substr( 0, RECORD_HEADER_SIZE ) );
    uint32_t len = head.payloadLength;
    uint32_t expectedTotalLength = ( RECORD_HEADER_SIZE + len + 1 /*checksum*/ ) * 2 + 2;
    std::string data = str.substr( RECORD_HEADER_SIZE, str.size() - RECORD_HEADER_SIZE );

    if( expectedTotalLength != input.size() ) {
        std::stringstream ss;
        ss << "Expected: " << expectedTotalLength << ", Got: " << input.size();
        logger::error( ss.str() );
        throw "Error, invalid length";
    }
    if( checksum != -1 || error || dlen < RECORD_HEADER_SIZE ) {
        throw "Error, invalid checksum";
    }

    data.pop_back();

    return data;
}

/*
int main( int argc, char* argv[] ) {
    OpensslBIOWrapper *bio = new OpensslBIOWrapper(BIO_new_fd(0, 0));
    std::string data = "halloPayload";
    RecordHeader head;
    head.command = 0x7;
    head.flags = 1;
    head.sessid = 13;
    head.command_count = 0xA0B;
    head.totalLength = 9;
    sendCommand( head, data, std::shared_ptr<OpensslBIO>(bio) );
    head.command = 0x8;

    try {
        std::string c = parseCommand( head, ":0700010D0000000B0A0900000000000C0068616C6C6F5061796C6F6164E6\n" );

        std::cout << "res: " << std::endl;
        std::cout << head.payloadLength << std::endl;
        std::cout << c << std::endl;
    } catch( char const* c ) {
        std::cout << "err: " << c << std::endl;
    }


    return 0;
}
*/
