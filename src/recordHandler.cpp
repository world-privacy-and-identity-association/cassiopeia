#include "recordHandler.h"

#include <iostream>

#include <openssl/ssl.h>

#include "database.h"
#include "record.h"
#include "opensslBIO.h"

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
        BIO* bio = BIO_new( BIO_f_ssl() );
        SSL_set_accept_state( ssl );
        SSL_set_bio( ssl, output, output );
        BIO_set_ssl( bio, ssl, BIO_NOCLOSE );
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
        currentSession = std::shared_ptr<RecordHandlerSession>( new RecordHandlerSession( this, signer, ctx, bio ) );
    }

    currentSession->work();
}
