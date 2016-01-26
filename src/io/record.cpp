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
    size_t pos = 0;
    head.offset = 0;
    head.totalLength = data.size();
    do {
        size_t toTransfer = std::min(static_cast<size_t>(0xF000), data.size() - pos);
        head.payloadLength = toTransfer;

        std::string s;
        s += head.packToString();
        s += data.substr(pos, toTransfer);

        std::string res = toHexAndChecksum( s );

        logger::debug( "FINE: RECORD output: ", res );

        bio->write( res.data(), res.size() );

        pos += toTransfer;
        head.offset += 1;
    } while(pos < data.size());
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
std::string parseCommandChunked( RecordHeader& head, std::shared_ptr<OpensslBIOWrapper> io){
    logger::note("reading");
    std::string payload = parseCommand( head, io->readLine() );
    std::string all(head.totalLength, ' ');
    auto target = all.begin();
    size_t pos = 0;
    RecordHeader head2;
    while(true) {
        pos += head.payloadLength;
        target = std::copy ( payload.begin(), payload.end(), target);
        if(pos >= head.totalLength) {
            break;
        }
        logger::note("chunk digested, reading next one");
        payload = parseCommand( head2, io->readLine() );
        if(!head2.isFollowupOf(head)){
            throw std::runtime_error("Error, header of follow up chunk was malformed");
        }
        head = head2;
    }
    return all;
}
