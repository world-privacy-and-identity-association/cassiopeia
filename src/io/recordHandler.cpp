#include "io/recordHandler.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <ctime>
#include <unordered_map>

#include <openssl/ssl.h>

#include "util.h"
#include "io/record.h"
#include "io/opensslBIO.h"
#include "io/slipBio.h"

#include "db/database.h"
#include "crypto/remoteSigner.h"
#include "crypto/sslUtil.h"
#include "crypto/simpleOpensslSigner.h"

#include "log/logger.hpp"

extern std::vector<Profile> profiles;
extern std::unordered_map<std::string, std::shared_ptr<CAConfig>> CAs;

class RecordHandlerSession {
public:
    uint32_t sessid = 0;
    uint32_t lastCommandCount = 0;

    std::shared_ptr<TBSCertificate> tbs;
    std::shared_ptr<SignedCertificate> result;

    std::shared_ptr<SSL> ssl;

    std::shared_ptr<OpensslBIOWrapper> io;
    DefaultRecordHandler* parent;
    std::shared_ptr<Signer> signer;

    std::unique_ptr<std::ofstream> logFile;
    //std::stringstream sessionlog;
    std::vector<std::string> serials;
    logger::logger_set logger;


    RecordHandlerSession( DefaultRecordHandler* parent, std::shared_ptr<Signer> signer, std::shared_ptr<SSL_CTX> ctx, std::shared_ptr<BIO> output ) :
        tbs( std::make_shared<TBSCertificate>() ),
        logFile( openLogfile( "logs/log_" + timestamp() ) ),
        logger{ std::cout, *logFile } {
        this->parent = parent;
        this->signer = signer;

        ssl = std::shared_ptr<SSL>( SSL_new( ctx.get() ), SSL_free );
        std::shared_ptr<BIO> bio(
            BIO_new( BIO_f_ssl() ),
            [output]( BIO * p ) {
                BIO_free( p );
            } );
        SSL_set_accept_state( ssl.get() );
        SSL_set_bio( ssl.get(), output.get(), output.get() );
        BIO_set_ssl( bio.get(), ssl.get(), BIO_NOCLOSE );
        io = std::make_shared<OpensslBIOWrapper>( bio );
    }

    void respondCommand( RecordHeader::SignerResult res, std::string payload ) {
        RecordHeader rh;
        rh.command = static_cast<uint16_t>( res );
        rh.flags = 0;
        rh.command_count = 0; // TODO i++
        sendCommand( rh, payload, io );
    }

    void work() {
        try {
            RecordHeader head;
            std::string all = parseCommandChunked( head, io );
            execute( static_cast<RecordHeader::SignerCommand>( head.command ), all );
        } catch( const std::exception& msg ) {
            logger::error( "ERROR: ", msg.what() );
            parent->reset();
            return;
        }
    }

    void execute( RecordHeader::SignerCommand command, std::string data ) {
        switch( command ) {
        case RecordHeader::SignerCommand::SET_CSR:
            tbs->csr_content = data;
            tbs->csr_type = "CSR";
            logger::note( "INFO: CSR read:\n", tbs->csr_content );
            break;

        case RecordHeader::SignerCommand::SET_SPKAC:
            tbs->csr_content = data;
            tbs->csr_type = "SPKAC";
            logger::note( "INFO: SPKAC read:\n", tbs->csr_content );
            break;

        case RecordHeader::SignerCommand::SET_SIGNATURE_TYPE:
            tbs->md = data;
            break;

        case RecordHeader::SignerCommand::SET_PROFILE:
            // TODO
            tbs->profile = data;
            break;

        case RecordHeader::SignerCommand::SET_WISH_FROM:
            tbs->wishFrom = data;
            break;

        case RecordHeader::SignerCommand::SET_WISH_TO:
            tbs->wishTo = data;
            break;

        case RecordHeader::SignerCommand::ADD_SAN:
            {
                size_t pos = data.find( "," );

                if( pos == std::string::npos ) {
                    // error
                } else {
                    auto san = std::make_shared<SAN>();
                    san->type = data.substr( 0, pos );
                    san->content = data.substr( pos + 1 );
                    tbs->SANs.push_back( san );
                }
            }
            break;

        case RecordHeader::SignerCommand::ADD_AVA:
            {
                size_t pos = data.find( "," );

                if( pos == std::string::npos ) {
                    // error
                } else {
                    auto ava = std::make_shared<AVA>();
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
            logger::note( "INFO: signlog:\n", result->log );
            logger::note( "INFO: res:\n", result->certificate );
            respondCommand( RecordHeader::SignerResult::SAVE_LOG, result->log );
            break;

        case RecordHeader::SignerCommand::LOG_SAVED:
            if( result ) {
                respondCommand( RecordHeader::SignerResult::SIGNING_CA, result->ca_name );
                respondCommand( RecordHeader::SignerResult::CERTIFICATE, result->certificate );
            }

            logger::note( "Shutting down SSL" );

            if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) {
                logger::warn( "ERROR: SSL shutdown failed." );
            }

            io->ctrl( BIO_CTRL_FLUSH, 0, NULL );
            logger::note( "Shutted down SSL" );

            parent->reset(); // Connection ended

            break;

        case RecordHeader::SignerCommand::ADD_SERIAL:
            serials.push_back( data );
            break;

        case RecordHeader::SignerCommand::REVOKE:
            {
                logger::note("Revoking: ", data);
                std::string ca = data;
                auto reqCA = CAs.at( ca );
                logger::note( "CA found in recordHandler" );
                std::shared_ptr<CRL> crl;
                std::string date;
                std::tie( crl, date ) = signer->revoke( reqCA, serials );

                respondCommand( RecordHeader::SignerResult::REVOKED, date + crl->getSignature() );
            }
            break;

        case RecordHeader::SignerCommand::GET_FULL_CRL:
            {
                logger::note("Requesting full CRL: ", data);
                auto ca = CAs.at( data );
                CRL c( ca->path + "/ca.crl" );
                respondCommand( RecordHeader::SignerResult::FULL_CRL, c.toString() );
                
                logger::note( "Shutting down SSL" );
                if( !SSL_shutdown( ssl.get() ) && !SSL_shutdown( ssl.get() ) ) {
                    logger::error( "ERROR: SSL shutdown failed." );
                }
                io->ctrl( BIO_CTRL_FLUSH, 0, NULL );
                logger::note( "Shutted down SSL" );

                parent->reset(); // Connection ended
            }
            break;

        default:
            throw std::runtime_error( "Unimplemented" );
        }
    }
};

DefaultRecordHandler::DefaultRecordHandler( std::shared_ptr<Signer> signer, std::shared_ptr<BIO> bio ) :
    bio( bio ), ctx( generateSSLContext( true ) ), signer( signer ), currentSession() {
}

void DefaultRecordHandler::reset() {
    currentSession = std::shared_ptr<RecordHandlerSession>();
}

void DefaultRecordHandler::handle() {
    if( !currentSession ) {
        ( void ) BIO_reset( bio.get() );
        logger::note( "New session allocated." );
        currentSession = std::make_shared<RecordHandlerSession>( this, signer, ctx, bio );
    }

    try {
        currentSession->work();
    } catch( eof_exception e ) {
        reset();
    }
}
