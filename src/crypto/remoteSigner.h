#pragma once
#include <memory>
#include <openssl/ssl.h>

#include "db/database.h"
#include "crypto/signer.h"
#include "io/bios.h"
#include "io/opensslBIO.h"
#include "io/record.h"


class RemoteSigner : public Signer {
private:
    std::shared_ptr<BIO> target;
    std::shared_ptr<SSL_CTX> ctx;
    std::shared_ptr<std::ostream> log;
    int count = 0;
    void send( std::shared_ptr<OpensslBIOWrapper> bio, RecordHeader& head, RecordHeader::SignerCommand cmd, std::string data );
public:
    RemoteSigner( std::shared_ptr<BIO> target, std::shared_ptr<SSL_CTX> ctx );
    ~RemoteSigner();
    std::shared_ptr<SignedCertificate> sign( std::shared_ptr<TBSCertificate> cert );
    std::pair<std::shared_ptr<CRL>, std::string> revoke( std::shared_ptr<CAConfig> ca, std::vector<std::string> serial );

    void setLog( std::shared_ptr<std::ostream> target );
};
