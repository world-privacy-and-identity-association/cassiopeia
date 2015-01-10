#include "remoteSigner.h"
#include "util.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bn.h>

RemoteSigner::RemoteSigner( std::shared_ptr<BIO> target, std::shared_ptr<SSL_CTX> ctx ) {
    this->target = target;
    this->ctx = ctx;
}

RemoteSigner::~RemoteSigner() {
}

void RemoteSigner::send( std::shared_ptr<OpensslBIOWrapper> bio, RecordHeader& head, RecordHeader::SignerCommand cmd, std::string data ) {
    head.command = ( uint16_t ) cmd;
    head.command_count++;
    head.totalLength = data.size();
    sendCommand( head, data, bio, log );

}

std::shared_ptr<SignedCertificate> RemoteSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    ( void )BIO_reset( target.get() );

    std::shared_ptr<SSL> ssl( SSL_new( ctx.get() ), SSL_free );
    std::shared_ptr<BIO> bio( BIO_new( BIO_f_ssl() ), BIO_free );
    SSL_set_connect_state( ssl.get() );
    SSL_set_bio( ssl.get(), target.get(), target.get() );
    BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
    std::shared_ptr<OpensslBIOWrapper> conn( new OpensslBIOWrapper( bio ) );
    RecordHeader head;
    head.flags = 0;
    head.sessid = 13;

    if( cert->csr_type == "CSR" ) {
        send( conn, head, RecordHeader::SignerCommand::SET_CSR, cert->csr_content );
    } else if( cert->csr_type == "SPKAC" ) {
        send( conn, head, RecordHeader::SignerCommand::SET_SPKAC, cert->csr_content );
    } else {
        std::cout << "Unknown csr_type: " << cert->csr_type;
        return std::shared_ptr<SignedCertificate>();
    }

    send( conn, head, RecordHeader::SignerCommand::SET_SIGNATURE_TYPE, cert->md );
    send( conn, head, RecordHeader::SignerCommand::SET_PROFILE, cert->profile );

    for( auto ava : cert->AVAs ) {
        if( ava->name.find( "," ) != std::string::npos ) {
            // invalid ava
            return std::shared_ptr<SignedCertificate>();
        }

        send( conn, head, RecordHeader::SignerCommand::ADD_AVA, ava->name + "," + ava->value );
    }

    for( auto san : cert->SANs ) {
        if( san->type.find( "," ) != std::string::npos ) {
            // invalid ava
            return std::shared_ptr<SignedCertificate>();
        }

        send( conn, head, RecordHeader::SignerCommand::ADD_SAN, san->type + "," + san->content );
    }

    send( conn, head, RecordHeader::SignerCommand::SIGN, "" );
    send( conn, head, RecordHeader::SignerCommand::LOG_SAVED, "" );
    std::shared_ptr<SignedCertificate> result = std::shared_ptr<SignedCertificate>( new SignedCertificate() );
    std::vector<char> buffer( 2048 * 4 );

    for( int i = 0; i < 3; i++ ) {
        try {
            int length = conn->read( buffer.data(), buffer.size() );

            if( length <= 0 ) {
                std::cout << "Error, no response data" << std::endl;
                result = std::shared_ptr<SignedCertificate>();
                break;
            }

            RecordHeader head;
            std::string payload = parseCommand( head, std::string( buffer.data(), length ), log );

            switch( ( RecordHeader::SignerResult ) head.command ) {
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
                std::cout << "Invalid Message" << std::endl;
                break;
            }
        } catch( const char* msg ) {
            std::cout << msg << std::endl;
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
        result->serial = std::string( serStr.get() );
    }

    if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) { // need to close the connection twice
        std::cout << "SSL shutdown failed" << std::endl;
    }

    return result;
}

std::pair<std::shared_ptr<CRL>, std::string> RemoteSigner::revoke( std::shared_ptr<CAConfig> ca, std::string serial ) {
    ( void )BIO_reset( target.get() );

    std::shared_ptr<SSL> ssl( SSL_new( ctx.get() ), SSL_free );
    std::shared_ptr<BIO> bio( BIO_new( BIO_f_ssl() ), BIO_free );
    SSL_set_connect_state( ssl.get() );
    SSL_set_bio( ssl.get(), target.get(), target.get() );
    BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
    std::shared_ptr<OpensslBIOWrapper> conn( new OpensslBIOWrapper( bio ) );

    RecordHeader head;
    head.flags = 0;
    head.sessid = 13;

    std::string payload = ca->name + std::string( "\0", 1 ) + serial;
    send( conn, head, RecordHeader::SignerCommand::REVOKE, payload );

    std::vector<char> buffer( 2048 * 4 );
    int length = conn->read( buffer.data(), buffer.size() );

    if( length <= 0 ) {
        throw "Error, no response data";
    }

    payload = parseCommand( head, std::string( buffer.data(), length ), log );

    std::shared_ptr<CRL> crl( new CRL( ca->path + std::string( "/ca.crl" ) ) );
    std::string date;

    if( ( RecordHeader::SignerResult ) head.command != RecordHeader::SignerResult::REVOKED ) {
        throw "Protocol violation";
    }

    const unsigned char* buffer2 = ( const unsigned char* ) payload.data();
    const unsigned char* pos = buffer2;
    ASN1_TIME* time = d2i_ASN1_TIME( NULL, &pos, payload.size() );
    ASN1_TIME_free( time );
    date = payload.substr( 0, pos - buffer2 );
    std::string rest = payload.substr( pos - buffer2 );
    crl->revoke( serial, date );
    crl->setSignature( rest );
    bool ok = crl->verify( ca );

    if( ok ) {
        ( *log ) << "CRL verificated successfully" << std::endl;
        writeFile( ca->path + std::string( "/ca.crl" ), crl->toString() );
    } else {
        ( *log ) << "CRL is broken" << std::endl;
        send( conn, head, RecordHeader::SignerCommand::GET_FULL_CRL, ca->name );
        length = conn->read( buffer.data(), buffer.size() );

        if( length <= 0 ) {
            throw "Error, no response data";
        }

        payload = parseCommand( head, std::string( buffer.data(), length ), log );

        if( ( RecordHeader::SignerResult ) head.command != RecordHeader::SignerResult::FULL_CRL ) {
            throw "Protocol violation";
        }

        writeFile( ca->path + std::string( "/ca.crl.bak" ), payload );
        crl = std::shared_ptr<CRL>( new CRL( ca->path + std::string( "/ca.crl.bak" ) ) );

        if( crl->verify( ca ) ) {
            writeFile( ca->path + std::string( "/ca.crl" ), crl->toString() );
            ( *log ) << "CRL is now valid" << std::endl;
        } else {
            ( *log ) << "CRL is still broken... Please, help me" << std::endl;
        }

    }

    ( *log ) << "CRL: " << std::endl << crl->toString() << std::endl;

    if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) { // need to close the connection twice
        std::cout << "SSL shutdown failed" << std::endl;
    }

    return std::pair<std::shared_ptr<CRL>, std::string>( crl, date );
}

void RemoteSigner::setLog( std::shared_ptr<std::ostream> target ) {
    this->log = target;
}
