#pragma once
#include <memory>
#include <openssl/ssl.h>

#include "database.h"
#include "signer.h"
#include "bios.h"
#include "opensslBIO.h"
#include "record.h"


class RemoteSigner : public Signer {
private:
    std::shared_ptr<BIO> target;
    std::shared_ptr<SSL_CTX> ctx;
    int count = 0;
    void send( std::shared_ptr<OpensslBIOWrapper> bio, RecordHeader& head, RecordHeader::SignerCommand cmd, std::string data );
public:
    RemoteSigner( std::shared_ptr<BIO> target, std::shared_ptr<SSL_CTX> ctx );
    ~RemoteSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
};