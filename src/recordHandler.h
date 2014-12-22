#pragma once

#include <memory>
#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "record.h"
#include "signer.h"

class RecordHandler {
public:
    virtual void handle( std::string data ) = 0;
    virtual void reset() = 0;
};

class RecordHandlerSession;

class DefaultRecordHandler {
private:
    std::shared_ptr<BIO> bio;
    std::shared_ptr<SSL_CTX> ctx;
    std::shared_ptr<Signer> signer;
    std::shared_ptr<RecordHandlerSession> currentSession;
public:
    DefaultRecordHandler( std::shared_ptr<Signer> signer, std::shared_ptr<BIO> bio );
    void handle();
    void reset();
};
