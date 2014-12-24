#include "sslUtil.h"

#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <iostream>

std::shared_ptr<int> ssl_lib_ref(
    new int( SSL_library_init() ),
    []( int* ref ) {
        delete ref;

        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    } );

int gencb( int a, int b, BN_GENCB* g ) {
    ( void ) a;
    ( void ) b;
    ( void ) g;
    std::cout << ( a == 0 ? "." : "+" ) << std::flush;
    return 1;
}

static int verify_callback( int preverify_ok, X509_STORE_CTX* ctx ) {
    if( !preverify_ok ) {
        //auto cert = X509_STORE_CTX_get_current_cert(ctx);
        //BIO *o = BIO_new_fp(stdout,BIO_NOCLOSE);
        //X509_print_ex(o, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
        //BIO_free(o);

        std::cout << "Verification failed: " << preverify_ok << " because " << X509_STORE_CTX_get_error( ctx ) << std::endl;
    }

    return preverify_ok;
}

static std::shared_ptr<DH> dh_param;

std::shared_ptr<SSL_CTX> generateSSLContext( bool server ) {
    std::shared_ptr<SSL_CTX> ctx = std::shared_ptr<SSL_CTX>( SSL_CTX_new( TLSv1_2_method() ), []( SSL_CTX * p ) {
        SSL_CTX_free( p );
    } );

    if( !SSL_CTX_set_cipher_list( ctx.get(), "HIGH:+CAMELLIA256:!eNull:!aNULL:!ADH:!MD5:-RSA+AES+SHA1:!RC4:!DES:!3DES:!SEED:!EXP:!AES128:!CAMELLIA128" ) ) {
        throw "Cannot set cipher list. Your source is broken.";
    }

    SSL_CTX_set_verify( ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback );
    SSL_CTX_use_certificate_file( ctx.get(), server ? "keys/signer_server.crt" : "keys/signer_client.crt", SSL_FILETYPE_PEM );
    SSL_CTX_use_PrivateKey_file( ctx.get(), server ? "keys/signer_server.key" : "keys/signer_client.key", SSL_FILETYPE_PEM );
    SSL_CTX_load_verify_locations( ctx.get(), "keys/ca.crt", 0 );

    if( server ) {
        STACK_OF( X509_NAME ) *names = SSL_load_client_CA_file( "keys/env.crt" );

        if( names ) {
            SSL_CTX_set_client_CA_list( ctx.get(), names );
        } else {
            // error
        }

        if( !dh_param ) {
            FILE* paramfile = fopen( "dh_param.pem", "r" );

            if( paramfile ) {
                dh_param = std::shared_ptr<DH>( PEM_read_DHparams( paramfile, NULL, NULL, NULL ), DH_free );
                fclose( paramfile );
            } else {
                dh_param = std::shared_ptr<DH>( DH_new(), DH_free );
                std::cout << "Generating DH params" << std::endl;
                BN_GENCB cb;
                cb.ver = 2;
                cb.arg = 0;
                cb.cb.cb_2 = gencb;

                if( !DH_generate_parameters_ex( dh_param.get(), 2048, 5, &cb ) ) {
                    throw "DH generation failed";
                }

                std::cout << std::endl;
                paramfile = fopen( "dh_param.pem", "w" );

                if( paramfile ) {
                    PEM_write_DHparams( paramfile, dh_param.get() );
                    fclose( paramfile );
                }
            }
        }

        if( !SSL_CTX_set_tmp_dh( ctx.get(), dh_param.get() ) ) {
            throw "Cannot set tmp dh.";
        }
    }

    return ctx;
}

void setupSerial( FILE* f ) {
    struct termios attr;

    if( tcgetattr( fileno( f ), &attr ) ) {
        throw "failed to get attrs";
    }

    attr.c_iflag &= ~( IGNBRK | BRKINT | PARMRK | ISTRIP
                       | INLCR | IGNCR | ICRNL | IXON );
    attr.c_oflag &= ~OPOST;
    attr.c_lflag &= ~( ECHO | ECHONL | ICANON | ISIG | IEXTEN );
    attr.c_cflag &= ~( CSIZE | PARENB );
    attr.c_cflag |= CS8;

    cfsetispeed( &attr, B115200 );
    cfsetospeed( &attr, B115200 );

    if( tcsetattr( fileno( f ), TCSANOW, &attr ) ) {
        throw "failed to get attrs";
    }
}

std::shared_ptr<BIO> openSerial( const char* name ) {
    FILE* f = fopen( name, "r+" );

    if( !f ) {
        std::cout << "Opening serial device failed" << std::endl;
        return std::shared_ptr<BIO>();
    }

    setupSerial( f );

    std::shared_ptr<BIO> b( BIO_new_fd( fileno( f ), 0 ), BIO_free );
    return b;
}