#include "remoteSigner.h"

#include <iostream>

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
    sendCommand( head, data, bio );

}

std::shared_ptr<SignedCertificate> RemoteSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
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

    for( int i = 0; i < 2; i++ ) {
        try {
            int length = conn->read( buffer.data(), buffer.size() );
            RecordHeader head;
            std::string payload = parseCommand( head, std::string( buffer.data(), length ) );

            switch( ( RecordHeader::SignerResult ) head.command ) {
            case RecordHeader::SignerResult::CERTIFICATE:
                result->certificate = payload;
                break;

            case RecordHeader::SignerResult::SAVE_LOG:
                result->log = payload;
                break;
            }
        } catch( const char* msg ) {
            std::cout << msg << std::endl;
            return std::shared_ptr<SignedCertificate>();
        }
    }

    return result;
}

