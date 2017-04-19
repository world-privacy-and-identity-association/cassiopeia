#pragma once

#include <inttypes.h>

#include <memory>
#include <string>
#include <exception>
#include "bios.h"
#include "io/opensslBIO.h"

#define RECORD_HEADER_SIZE 17

class RecordHeader {
public:
    enum class SignerCommand : uint16_t {
        SET_CSR = 0x01,
        SET_SPKAC = 0x02,
        SET_SIGNATURE_TYPE = 0x10,
        SET_PROFILE = 0x11,
        SET_WISH_FROM = 0x12,
        SET_WISH_TO = 0x13,
        ADD_SAN = 0x18,
        ADD_AVA = 0x19,
        ADD_PROOF_LINE = 0x40,
        SIGN = 0x80,
        LOG_SAVED = 0x81,
        REVOKE = 0x100,
        GET_FULL_CRL = 0x101,
        ADD_SERIAL = 0x102,
        GET_TIMESTAMP = 0xC0,
        GET_STATUS_REPORT = 0xD0
    };

    enum class SignerResult : uint16_t {
        REVOKED = 0x100,
        FULL_CRL = 0x101,
        SAVE_LOG = 0x80,
        CERTIFICATE = 0x81,
        SIGNING_CA = 0x82,
    };

public:
    uint16_t command;
    char flags;
    uint32_t sessid;
    uint16_t command_count;
    uint32_t totalLength;
    uint16_t offset;
    uint16_t payloadLength;

    RecordHeader() :
        command( 0 ), flags( 0 ), sessid( 0 ), command_count( 0 ), totalLength( 0 ), offset( 0 ), payloadLength( 0 ) {
    }

    template <class T>
    static void append( std::string& str, T val ) {
        str.append( ( char* ) &val, sizeof( T ) );
    }

    template <class T>
    static void read( std::string::const_iterator& it, T& val ) {
        union typeConversion {
            char buf[sizeof( T )];
            T value;

            typeConversion( const T& v ) : value( v ) {}
        };

        typeConversion data( 0 );

        for( size_t i = 0; i < sizeof( T ); i++ ) {
            data.buf[i] = *it++;
        }

        val = data.value;
    }

    std::string packToString() {
        std::string res;
        res.reserve( RECORD_HEADER_SIZE );
        append( res, command );
        append( res, flags );
        append( res, sessid );
        append( res, command_count );
        append( res, totalLength );
        append( res, offset );
        append( res, payloadLength );
        return res;
    }

    void unpackFromString( const std::string& str ) {
        if( str.size() != RECORD_HEADER_SIZE ) {
            throw std::runtime_error( "Invalid string length" );
        }

        auto it =  str.cbegin();
        read( it, command );
        read( it, flags );
        read( it, sessid );
        read( it, command_count );
        read( it, totalLength );
        read( it, offset );
        read( it, payloadLength );
    }
    bool isFollowupOf( const RecordHeader& head ) {
        return head.command == command && head.flags == flags && head.sessid == sessid && head.command_count == command_count && head.totalLength == totalLength && head.offset + 1 == offset;
    }
};

std::string parseCommand( RecordHeader& head, const std::string& input );
std::string parseCommandChunked( RecordHeader& head, std::shared_ptr<OpensslBIOWrapper> conn );

void sendCommand( RecordHeader& head, const std::string& data, std::shared_ptr<OpensslBIO> bio );
