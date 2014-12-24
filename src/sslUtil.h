#pragma once
#include <openssl/ssl.h>
#include <memory>

extern std::shared_ptr<int> ssl_lib_ref;

std::shared_ptr<SSL_CTX> generateSSLContext( bool server );
std::shared_ptr<BIO> openSerial( const char* name );
