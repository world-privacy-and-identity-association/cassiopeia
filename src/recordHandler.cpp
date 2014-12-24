#include "recordHandler.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <unistd.h>

#include <iostream>

#include <openssl/ssl.h>

#include "database.h"
#include "record.h"
#include "opensslBIO.h"
#include "remoteSigner.h"
#include "simpleOpensslSigner.h"
#include "sslUtil.h"
#include "slipBio.h"

class RecordHandlerSession {
public:
    uint32_t sessid;
    uint32_t lastCommandCount;

    std::shared_ptr<TBSCertificate> tbs;
    std::shared_ptr<SignedCertificate> result;

    SSL* ssl;

    std::shared_ptr<OpensslBIOWrapper> io;
    DefaultRecordHandler* parent;
    std::shared_ptr<Signer> signer;

    RecordHandlerSession( DefaultRecordHandler* parent, std::shared_ptr<Signer> signer, std::shared_ptr<SSL_CTX> ctx, std::shared_ptr<BIO> output ) :
        tbs( new TBSCertificate() ) {
        this->parent = parent;
        this->signer = signer;

        ssl = SSL_new( ctx.get() );
        std::shared_ptr<BIO> bio(
            BIO_new( BIO_f_ssl() ),
            [output]( BIO * p ) {
                BIO_free( p );
            } );
        SSL_set_accept_state( ssl );
        SSL_set_bio( ssl, output.get(), output.get() );
        BIO_set_ssl( bio.get(), ssl, BIO_NOCLOSE );
        io = std::shared_ptr<OpensslBIOWrapper>( new OpensslBIOWrapper( bio ) );
    }

    void respondCommand( RecordHeader::SignerResult res, std::string payload ) {
        RecordHeader rh;
        rh.command = ( uint16_t ) res;
        rh.flags = 0;
        rh.command_count = 0; // TODO i++
        rh.totalLength = payload.size();
        sendCommand( rh, payload, io );
    }

    void work() {
        std::cout << "done" << std::endl;
        std::vector<char> buffer( 2048, 0 );
        std::cout << "reading" << std::endl;
        int res = io->read( buffer.data(), buffer.capacity() );
        std::cout << "read" << std::endl;

        if( res <= 0 ) {
            parent->reset();
            return;
        }

        std::string content( buffer.data(), res );

        try {
            RecordHeader head;
            std::string payload = parseCommand( head, content );
            execute( head, payload );
        } catch( const char* msg ) {
            std::cout << msg << std::endl;
            parent->reset();
            return;
        }
    }

    void execute( RecordHeader& head, std::string data ) {
        if( head.totalLength != head.payloadLength || head.offset != 0 ) {
            throw "Error, chunking not supported yet";
        }

        switch( ( RecordHeader::SignerCommand ) head.command ) {
        case RecordHeader::SignerCommand::SET_CSR: // setCSR
            tbs->csr_content = data;
            tbs->csr_type = "CSR";
            std::cout << "CSR read" << std::endl;
            break;

        case RecordHeader::SignerCommand::SET_SIGNATURE_TYPE:
            tbs->md = data;
            break;

        case RecordHeader::SignerCommand::SET_PROFILE:
            // TODO
            tbs->profile = data;
            break;

        case RecordHeader::SignerCommand::ADD_SAN: {
            size_t pos = data.find( "," );

            if( pos == std::string::npos ) {
            } else {
                std::shared_ptr<SAN> san( new SAN() );
                san->type = data.substr( 0, pos );
                san->content = data.substr( pos + 1 );
                tbs->SANs.push_back( san );
            }
        }
        break;

        case RecordHeader::SignerCommand::ADD_AVA: {
            size_t pos = data.find( "," );

            if( pos == std::string::npos ) {
                // error
            } else {
                std::shared_ptr<AVA> ava( new AVA() );
                ava->name = data.substr( 0, pos );
                ava->value = data.substr( pos + 1 );
                tbs->AVAs.push_back( ava );
            }
        }
        break;

        case RecordHeader::SignerCommand::ADD_PROOF_LINE:
            break;

        case RecordHeader::SignerCommand::SIGN:
            result = signer->sign( tbs );
            std::cout << "res: " << result->certificate << std::endl;
            result->log = "I am a dummy log.\nI signed that thing ;-) \n";
            respondCommand( RecordHeader::SignerResult::SAVE_LOG, result->log );
            break;

        case RecordHeader::SignerCommand::LOG_SAVED:
            if( result ) {
                respondCommand( RecordHeader::SignerResult::CERTIFICATE, result->certificate );
            }

            break;

        default:
            throw "Unimplemented";
        }
    }
};

DefaultRecordHandler::DefaultRecordHandler( std::shared_ptr<Signer> signer, std::shared_ptr<BIO> bio ) :
    currentSession() {

    this->signer = signer;

    ctx = generateSSLContext( true );

    this->bio = bio;
}

void DefaultRecordHandler::reset() {
    currentSession = std::shared_ptr<RecordHandlerSession>();
}

void DefaultRecordHandler::handle() {
    if( !currentSession ) {
        std::cout << "session allocated" << std::endl;
        currentSession = std::shared_ptr<RecordHandlerSession>( new RecordHandlerSession( this, signer, ctx, bio ) );
    }

    std::cout << "really allocated: " << currentSession << ";" << std::endl;
    currentSession->work();
}

int handlermain( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;

    std::shared_ptr<OpensslBIOWrapper> bio( new OpensslBIOWrapper( std::shared_ptr<BIO>( BIO_new_fd( 0, 0 ), BIO_free ) ) );
    std::string data =
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIIBSzCBtQIBADAMMQowCAYDVQQDDAFhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
        "iQKBgQDerBEpIShJlx3zzl4AOS1NcwEg4iAWknQeTtI8B5dnk+l5HkOdTxqeehZn\n"
        "iZnuIuYXA+JWmoECg/w69+N5zw2BabelgK3cSvRqycwPEU/gceGJZTaBfkkN0hBk\n"
        "rpXDiLSlox5oeR150MrsHvVc+W2e+0jW1tuhz4QLzn8/uI/toQIDAQABoAAwDQYJ\n"
        "KoZIhvcNAQELBQADgYEATQU5VrgQAkvpCvIwRUyjj9YAa9E014tNY0jMcBdv95fy\n"
        "/f49zIcVtUJuZuEwY6uDZQqfAm+8CLNpOCICH/Qw7YOe+s/Yw7a8rk5VqLtgxR4M\n"
        "z6DUeVL0zYFoLUxIje9yDU3pWmPvyVaBPdo0DguZwFMfiWwzhkUDeQgyeaiMvQA=\n"
        "-----END CERTIFICATE REQUEST-----";

    RecordHeader head;
    head.flags = 0;
    head.sessid = 13;

    //---

    std::shared_ptr<int> ssl_lib = ssl_lib_ref;

    if( argc >= 2 ) {
        std::shared_ptr<BIO> b = openSerial( "/dev/ttyUSB0" );
        std::shared_ptr<BIO> slip1( BIO_new( toBio<SlipBIO>() ), BIO_free );
        ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( b ) ) );
        std::shared_ptr<RemoteSigner> sign( new RemoteSigner( slip1, generateSSLContext( false ) ) );

        std::shared_ptr<TBSCertificate> cert( new TBSCertificate() );
        cert->csr_type = "csr";
        cert->csr_content = data;
        cert->md = "sha256";
        cert->profile = "1";
        std::shared_ptr<AVA> ava( new AVA() );
        ava->name = "CN";
        ava->value = "Dummy user certificates";
        cert->AVAs.push_back( ava );
        std::shared_ptr<SAN> san( new SAN() );
        san->type = "DNS";
        san->content = "n42.example.com";
        cert->SANs.push_back( san );

        auto res = sign->sign( cert );
        std::cout << "log: " << res->log << std::endl;
        std::cout << "cert things: " << res->certificate << std::endl;
        return 0;
    }

    std::shared_ptr<BIO> conn = openSerial( "/dev/ttyS0" );
    std::shared_ptr<BIO> slip1( BIO_new( toBio<SlipBIO>() ), BIO_free );

    ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( conn ) ) );

    try {
        DefaultRecordHandler* dh = new DefaultRecordHandler( std::shared_ptr<Signer>( new SimpleOpensslSigner() ), slip1 );

        while( true ) {
            dh->handle();
        }
    } catch( char const* ch ) {
        std::cout << "Exception: " << ch << std::endl;
    }

    return 0;
}
