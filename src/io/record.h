#pragma once

#include <inttypes.h>

#include <memory>
#include <string>

#include "bios.h"

#define RECORD_HEADER_SIZE 17

class RecordHeader {
public:
    enum class SignerCommand : uint16_t {
        SET_CSR = 0x01,
        SET_SPKAC = 0x02,
        SET_SIGNATURE_TYPE = 0x10,
        SET_PROFILE = 0x11,
        ADD_SAN = 0x18,
        ADD_AVA = 0x19,
        ADD_PROOF_LINE = 0x40,
        SIGN = 0x80,
        LOG_SAVED = 0x81,
        REVOKE = 0x100,
        GET_FULL_CRL = 0x101,
        GET_TIMESTAMP = 0xC0,
        GET_STATUS_REPORT = 0xD0
    };

    enum class SignerResult : uint16_t {
        REVOKED = 0x100,
        FULL_CRL = 0x101,
        SAVE_LOG = 0x80,
        CERTIFICATE = 0x81
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
    void append( std::string& str, T val ) {
        str.append( ( char* ) &val, sizeof( T ) );
    }

    template <class T>
    void read( std::string::iterator& it, T& val ) {
        char* data = ( char* ) &val;

        for( size_t i = 0; i < sizeof( T ); i++ ) {
            data[i] = *it;
            it++;
        }
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

    void unpackFromString( std::string str ) {
        if( str.size() != RECORD_HEADER_SIZE ) {
            throw "Invalid string length";
        }

        auto it =  str.begin();
        read( it, command );
        read( it, flags );
        read( it, sessid );
        read( it, command_count );
        read( it, totalLength );
        read( it, offset );
        read( it, payloadLength );
    }

};

std::string parseCommand( RecordHeader& head, const std::string input, std::shared_ptr<std::ostream> log );

void sendCommand( RecordHeader& head, const std::string& data, std::shared_ptr<OpensslBIO> bio, std::shared_ptr<std::ostream> log );
