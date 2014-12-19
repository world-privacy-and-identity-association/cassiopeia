#include "recordHandler.h"

#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>

#include <openssl/ssl.h>

#include "database.h"
#include "record.h"
#include "opensslBIO.h"
#include "simpleOpensslSigner.h"
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

    RecordHandlerSession( DefaultRecordHandler* parent, std::shared_ptr<Signer> signer, std::shared_ptr<SSL_CTX> ctx, BIO* output ) :
        tbs( new TBSCertificate() ) {
        this->parent = parent;
        this->signer = signer;

        ssl = SSL_new( ctx.get() );
        BIO* bio = output;//BIO_new( BIO_f_ssl() );
        //SSL_set_accept_state( ssl );
        //SSL_set_bio( ssl, output, output );
        //BIO_set_ssl( bio, ssl, BIO_NOCLOSE );
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
        std::vector<char> buffer( 2048, 0 );
        int res = io->read( buffer.data(), buffer.capacity() );

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
            tbs->md = "sha256"; // TODO use content ;-)
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

DefaultRecordHandler::DefaultRecordHandler( std::shared_ptr<Signer> signer, BIO* bio ) :
    currentSession() {

    this->signer = signer;

    ctx = std::shared_ptr<SSL_CTX>( SSL_CTX_new( TLSv1_method() ), SSL_CTX_free );
    SSL_CTX_use_certificate_file( ctx.get(), "testdata/server.crt", SSL_FILETYPE_PEM );
    SSL_CTX_use_PrivateKey_file( ctx.get(), "testdata/server.key", SSL_FILETYPE_PEM );

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

    currentSession->work();
}

int count = 0;
void send( std::shared_ptr<OpensslBIOWrapper> bio, RecordHeader& head, RecordHeader::SignerCommand cmd, std::string data ) {
    head.command = ( uint16_t ) cmd;
    head.command_count++;
    head.totalLength = data.size();
    sendCommand( head, data, bio );
}

void setupSerial( FILE* f ) {
    struct termios attr;

    if( tcgetattr( fileno( f ), &attr ) ) {
        throw "failed to get attrs";
    }

    attr.c_iflag &= ~( IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON );
    attr.c_oflag &= ~OPOST;
    attr.c_lflag &= ~( ECHO | ECHONL | ICANON | ISIG | IEXTEN );
    attr.c_cflag &= ~( CSIZE | PARENB );
    attr.c_cflag |= CS8;

    if( tcsetattr( fileno( f ), TCSANOW, &attr ) ) {
        throw "failed to get attrs";
    }
}

int handlermain( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;
    std::shared_ptr<OpensslBIOWrapper> bio( new OpensslBIOWrapper( BIO_new_fd( 0, 0 ) ) );
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

    SSL_library_init();

    if( argc >= 2 ) {
        FILE* f = fopen( "/dev/ttyUSB0", "r+" );

        if( !f ) {
            std::cout << "Opening /dev/ttyUSB0 bio failed" << std::endl;
            return -1;
        }

        setupSerial( f );

        BIO* b = BIO_new_fd( fileno( f ), 0 );
        BIO* slip1 = BIO_new( toBio<SlipBIO>() );
        ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( b ) ) );
        std::shared_ptr<OpensslBIOWrapper> conn( new OpensslBIOWrapper( slip1 ) );
        send( conn, head, RecordHeader::SignerCommand::SET_CSR, data );
        send( conn, head, RecordHeader::SignerCommand::SET_SIGNATURE_TYPE, "sha256" );
        send( conn, head, RecordHeader::SignerCommand::SET_PROFILE, "1" );
        send( conn, head, RecordHeader::SignerCommand::ADD_AVA, "CN,commonName" );
        send( conn, head, RecordHeader::SignerCommand::ADD_SAN, "DNS,*.example.com" );
        send( conn, head, RecordHeader::SignerCommand::SIGN, "" );
        send( conn, head, RecordHeader::SignerCommand::LOG_SAVED, "" );
        std::vector<char> buffer( 2048 * 4 );

        for( int i = 0; i < 2; i++ ) {
            try {
                int length = BIO_read( slip1, buffer.data(), buffer.size() );
                RecordHeader head;
                std::string payload = parseCommand( head, std::string( buffer.data(), length ) );
                std::cout << "Data: " << std::endl << payload << std::endl;
            } catch( const char* msg ) {
                std::cout << msg << std::endl;
                return -1;
            }
        }

        std::cout << "sent things" << std::endl;

        return 0;
    }

    FILE* f = fopen( "/dev/ttyS0", "r+" );

    if( !f ) {
        std::cout << "Opening /dev/ttyS0 bio failed" << std::endl;
        return -1;
    }

    setupSerial( f );

    BIO* conn =  BIO_new_fd( fileno( f ), 0 );
    BIO* slip1 = BIO_new( toBio<SlipBIO>() );
    ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( conn ) ) );
    DefaultRecordHandler* dh = new DefaultRecordHandler( std::shared_ptr<Signer>( new SimpleOpensslSigner() ), slip1 );

    try {
        while( true ) {
            dh->handle();
        }
    } catch( char const* ch ) {
        std::cout << "Exception: " << ch << std::endl;
    }

    return 0;
}
