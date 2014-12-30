#include "recordHandler.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <ctime>

#include <openssl/ssl.h>

#include "database.h"
#include "record.h"
#include "opensslBIO.h"
#include "remoteSigner.h"
#include "simpleOpensslSigner.h"
#include "sslUtil.h"
#include "slipBio.h"

extern std::vector<Profile> profiles;

class RecordHandlerSession {
public:
    uint32_t sessid;
    uint32_t lastCommandCount;

    std::shared_ptr<TBSCertificate> tbs;
    std::shared_ptr<SignedCertificate> result;

    std::shared_ptr<SSL> ssl;

    std::shared_ptr<OpensslBIOWrapper> io;
    DefaultRecordHandler* parent;
    std::shared_ptr<Signer> signer;

    std::shared_ptr<std::ofstream> log;

    RecordHandlerSession( DefaultRecordHandler* parent, std::shared_ptr<Signer> signer, std::shared_ptr<SSL_CTX> ctx, std::shared_ptr<BIO> output ) :
        tbs( new TBSCertificate() ) {
        this->parent = parent;
        this->signer = signer;
        time_t c_time;

        if( time( &c_time ) == -1 ) {
            throw "Error while fetching time?";
        }

        log = std::shared_ptr<std::ofstream>(
            new std::ofstream( std::string( "logs/log_" ) + std::to_string( c_time ) ),
            []( std::ofstream * ptr ) {
                ptr->close();
                delete ptr;
            } );

        ssl = std::shared_ptr<SSL>( SSL_new( ctx.get() ), SSL_free );
        std::shared_ptr<BIO> bio(
            BIO_new( BIO_f_ssl() ),
            [output]( BIO * p ) {
                BIO_free( p );
            } );
        SSL_set_accept_state( ssl.get() );
        SSL_set_bio( ssl.get(), output.get(), output.get() );
        BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
        io = std::shared_ptr<OpensslBIOWrapper>( new OpensslBIOWrapper( bio ) );
    }

    void respondCommand( RecordHeader::SignerResult res, std::string payload ) {
        RecordHeader rh;
        rh.command = ( uint16_t ) res;
        rh.flags = 0;
        rh.command_count = 0; // TODO i++
        rh.totalLength = payload.size();
        sendCommand( rh, payload, io, log );
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
            std::string payload = parseCommand( head, content, log );
            execute( head, payload );
        } catch( const char* msg ) {
            if( log ) {
                ( *log ) << "ERROR: " << msg << std::endl;
            }

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
            ( *log ) << "INFO: CSR read:" << std::endl << tbs->csr_content;
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
            ( *log ) << "INFO: signlog: " << result->log << std::endl;
            ( *log ) << "INFO: res: " << result->certificate << std::endl;
            respondCommand( RecordHeader::SignerResult::SAVE_LOG, result->log );
            break;

        case RecordHeader::SignerCommand::LOG_SAVED:
            if( result ) {
                respondCommand( RecordHeader::SignerResult::CERTIFICATE, result->certificate );
            }

            if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) {
                ( *log ) << "ERROR: SSL close failed" << std::endl;
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

    currentSession->work();
}
