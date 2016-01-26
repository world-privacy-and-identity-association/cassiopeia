#include "remoteSigner.h"

#include "log/logger.hpp"
#include "util.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bn.h>

RemoteSigner::RemoteSigner( std::shared_ptr<BIO> target, std::shared_ptr<SSL_CTX> ctx ) : target( target ), ctx( ctx ) {
}

RemoteSigner::~RemoteSigner() {
}

void RemoteSigner::send( std::shared_ptr<OpensslBIOWrapper> bio, RecordHeader& head, RecordHeader::SignerCommand cmd, std::string data ) {
    head.command = static_cast<uint16_t>( cmd );
    head.command_count++;
    head.totalLength = data.size();
    sendCommand( head, data, bio );
}

std::shared_ptr<SignedCertificate> RemoteSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    ( void )BIO_reset( target.get() );

    std::shared_ptr<SSL> ssl( SSL_new( ctx.get() ), SSL_free );
    std::shared_ptr<BIO> bio( BIO_new( BIO_f_ssl() ), BIO_free );
    SSL_set_connect_state( ssl.get() );
    SSL_set_bio( ssl.get(), target.get(), target.get() );
    BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
    auto conn = std::make_shared<OpensslBIOWrapper>( bio );
    RecordHeader head;
    head.flags = 0;
    head.sessid = 13;

    if( cert->csr_type == "CSR" ) {
        send( conn, head, RecordHeader::SignerCommand::SET_CSR, cert->csr_content );
    } else if( cert->csr_type == "SPKAC" ) {
        send( conn, head, RecordHeader::SignerCommand::SET_SPKAC, cert->csr_content );
    } else {
        logger::error( "Unknown csr_type: ", cert->csr_type );
        return nullptr;
    }

    send( conn, head, RecordHeader::SignerCommand::SET_SIGNATURE_TYPE, cert->md );
    send( conn, head, RecordHeader::SignerCommand::SET_PROFILE, cert->profile );
    send( conn, head, RecordHeader::SignerCommand::SET_WISH_FROM, cert->wishFrom );
    send( conn, head, RecordHeader::SignerCommand::SET_WISH_TO, cert->wishTo );

    for( auto &ava : cert->AVAs ) {
        if( ava->name.find( "," ) != std::string::npos ) {
            // invalid ava
            return nullptr;
        }

        send( conn, head, RecordHeader::SignerCommand::ADD_AVA, ava->name + "," + ava->value );
    }

    for( auto &san : cert->SANs ) {
        if( san->type.find( "," ) != std::string::npos ) {
            // invalid ava
            return nullptr;
        }

        send( conn, head, RecordHeader::SignerCommand::ADD_SAN, san->type + "," + san->content );
    }

    send( conn, head, RecordHeader::SignerCommand::SIGN, "" );
    send( conn, head, RecordHeader::SignerCommand::LOG_SAVED, "" );
    auto result = std::make_shared<SignedCertificate>();

    for( int i = 0; i < 3; i++ ) {
        try {
            RecordHeader head;
            std::string payload = parseCommandChunked( head, conn );

            switch( static_cast<RecordHeader::SignerResult>( head.command )) {
            case RecordHeader::SignerResult::CERTIFICATE:
                result->certificate = payload;
                break;

            case RecordHeader::SignerResult::SAVE_LOG:
                result->log = payload;
                break;

            case RecordHeader::SignerResult::SIGNING_CA:
                result->ca_name = payload;
                break;

            default:
                logger::error( "Invalid Message" );
                break;
            }
        } catch( const char* msg ) {
            logger::error( msg );
            return std::shared_ptr<SignedCertificate>();
        }
    }

    if( result ) {
        std::shared_ptr<BIO> bios( BIO_new( BIO_s_mem() ), BIO_free );
        const char* buf = result->certificate.data();
        unsigned int len = result->certificate.size();

        while( len > 0 ) {
            int dlen = BIO_write( bios.get(), buf, len );

            if( dlen <= 0 ) {
                throw "Memory error.";
            }

            len -= dlen;
            buf += dlen;
        }

        std::shared_ptr<X509> pem( PEM_read_bio_X509( bios.get(), NULL, 0, NULL ) );

        if( !pem ) {
            throw "Pem was not readable";
        }

        std::shared_ptr<BIGNUM> ser( ASN1_INTEGER_to_BN( pem->cert_info->serialNumber, NULL ), BN_free );
        std::shared_ptr<char> serStr(
            BN_bn2hex( ser.get() ),
            []( char* p ) {
                OPENSSL_free( p );
            } ); // OPENSSL_free is a macro...

        extractTimes( pem, result );

        result->serial = std::string( serStr.get() );
    }

    logger::note( "Closing SSL connection" );
    if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) { // need to close the connection twice
        logger::warn( "SSL shutdown failed" );
    }
    logger::note( "SSL connection closed" );

    return result;
}

std::pair<std::shared_ptr<CRL>, std::string> RemoteSigner::revoke( std::shared_ptr<CAConfig> ca, std::vector<std::string> serials ) {
    ( void )BIO_reset( target.get() );

    std::shared_ptr<SSL> ssl( SSL_new( ctx.get() ), SSL_free );
    std::shared_ptr<BIO> bio( BIO_new( BIO_f_ssl() ), BIO_free );
    SSL_set_connect_state( ssl.get() );
    SSL_set_bio( ssl.get(), target.get(), target.get() );
    BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
    auto conn = std::make_shared<OpensslBIOWrapper>( bio );

    RecordHeader head;
    head.flags = 0;
    head.sessid = 13;

    for( auto &serial : serials ) {
        send( conn, head, RecordHeader::SignerCommand::ADD_SERIAL, serial );
    }

    std::string payload = ca->name;
    send( conn, head, RecordHeader::SignerCommand::REVOKE, payload );

    payload = parseCommandChunked( head, conn );

    std::string tgtName = ca->path + std::string( "/ca.crl" );
    auto crl = std::make_shared<CRL>( tgtName );
    std::string date;

    if( static_cast<RecordHeader::SignerResult>( head.command ) != RecordHeader::SignerResult::REVOKED ) {
        throw "Protocol violation";
    }

    const unsigned char* buffer2 = reinterpret_cast<const unsigned char*>( payload.data() );
    const unsigned char* pos = buffer2;
    ASN1_TIME* time = d2i_ASN1_TIME( NULL, &pos, payload.size() );
    ASN1_TIME_free( time );
    date = payload.substr( 0, pos - buffer2 );
    std::string rest = payload.substr( pos - buffer2 );

    for( std::string &serial : serials ) {
        crl->revoke( serial, date );
    }

    crl->setSignature( rest );
    bool ok = crl->verify( ca );

    if( ok ) {
        logger::note( "CRL verificated successfully" );
        writeFile( tgtName, crl->toString() );
    } else {
        logger::warn( "CRL is broken, trying to recover" );
        send( conn, head, RecordHeader::SignerCommand::GET_FULL_CRL, ca->name );

        payload = parseCommandChunked( head, conn );

        if( static_cast<RecordHeader::SignerResult>( head.command ) != RecordHeader::SignerResult::FULL_CRL ) {
            throw "Protocol violation";
        }

        std::string name_bak = ca->path + std::string( "/ca.crl.bak" );
        writeFile( name_bak, payload );
        crl = std::make_shared<CRL>( name_bak );

        if( crl->verify( ca ) ) {
            if( rename( name_bak.c_str(), tgtName.c_str() ) != 0 ){
                logger::warn( "Moving new CRL over old CRL failed" );
            }
            logger::note( "CRL is now valid again" );
        } else {
            logger::warn( "CRL is still broken... Please, help me" );
        }
    }

    logger::note( "Closing SSL connection" );
    if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) { // need to close the connection twice
        logger::warn( "SSL shutdown failed" );
    }
    logger::note( "SSL connection closed" );

    return { crl, date };
}

void RemoteSigner::setLog( std::shared_ptr<std::ostream> target ) {
    this->log = target;
}
