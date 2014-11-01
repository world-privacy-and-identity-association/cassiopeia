#include "simpleOpensslSigner.h"

#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

void SimpleOpensslSigner::sign( std::shared_ptr<TBSCertificate> cert ) {
    std::cout << cert->CN << std::endl;
    BIO* in;
    in = BIO_new_mem_buf( const_cast<char*>( cert->csr_content.c_str() ), -1 );
    X509_REQ* req = PEM_read_bio_X509_REQ( in, NULL, NULL, NULL );

    if( req == NULL ) {
        std::cerr << "Error parsing CSR" << std::endl;
        return;
    }

    EVP_PKEY* pktmp = X509_REQ_get_pubkey( req );

    if( pktmp == NULL ) {
        std::cerr << "Error extracting pubkey" << std::endl;
        return;
    }

    std::cout << req << ";" << pktmp << std::endl;
    SSL_library_init();
    int i = X509_REQ_verify( req, pktmp );
    ERR_load_crypto_strings();
    ERR_print_errors_fp( stderr );
    std::cout << ERR_get_error() << std::endl;

    if( i < 0 ) {
        std::cerr << "Signature problems ... " << i << std::endl;
        return;
    } else if( i == 0 ) {
        std::cerr << "Signature did not match" << std::endl;
        return;
    } else {
        std::cerr << "Signature ok" << std::endl;
    }

}
