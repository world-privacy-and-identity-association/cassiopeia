#include "sslUtil.h"

#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <iostream>

#include "crypto/CRL.h"

std::shared_ptr<int> ssl_lib_ref(
    new int( SSL_library_init() ),
    []( int* ref ) {
        delete ref;

        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    } );

std::shared_ptr<X509> loadX509FromFile( const std::string& filename ) {
    std::shared_ptr<FILE> f( fopen( filename.c_str(), "r" ), fclose );

    if( !f ) {
        return std::shared_ptr<X509>();
    }

    X509* key = PEM_read_X509( f.get(), NULL, NULL, 0 );

    if( !key ) {
        return std::shared_ptr<X509>();
    }

    return std::shared_ptr<X509>(
        key,
        []( X509 * ref ) {
            X509_free( ref );
        } );
}

std::shared_ptr<EVP_PKEY> loadPkeyFromFile( const std::string& filename ) {
    std::shared_ptr<FILE> f( fopen( filename.c_str(), "r" ), fclose );

    if( !f ) {
        return std::shared_ptr<EVP_PKEY>();
    }

    EVP_PKEY* key = PEM_read_PrivateKey( f.get(), NULL, NULL, 0 );

    if( !key ) {
        return std::shared_ptr<EVP_PKEY>();
    }

    return std::shared_ptr<EVP_PKEY>(
        key,
        []( EVP_PKEY * ref ) {
            EVP_PKEY_free( ref );
        } );
}

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
    if( 1 != SSL_CTX_load_verify_locations( ctx.get(), "keys/ca.crt", 0 ) ) {
        throw "Cannot load CA store for certificate validation.";
    }

    if( server ) {
        STACK_OF( X509_NAME ) *names = SSL_load_client_CA_file( "keys/env.crt" );

        if( names ) {
            SSL_CTX_set_client_CA_list( ctx.get(), names );
        } else {
            // error
        }

        if( !dh_param ) {
            std::shared_ptr<FILE> paramfile( fopen( "dh_param.pem", "r" ), fclose );

            if( paramfile ) {
                dh_param = std::shared_ptr<DH>( PEM_read_DHparams( paramfile.get(), NULL, NULL, NULL ), DH_free );
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
                paramfile = std::shared_ptr<FILE>( fopen( "dh_param.pem", "w" ), fclose );

                if( paramfile ) {
                    PEM_write_DHparams( paramfile.get(), dh_param.get() );
                }
            }
        }

        if( !SSL_CTX_set_tmp_dh( ctx.get(), dh_param.get() ) ) {
            throw "Cannot set tmp dh.";
        }
    }

    return ctx;
}

void setupSerial( std::shared_ptr<FILE> f ) {
    struct termios attr;

    if( tcgetattr( fileno( f.get() ), &attr ) ) {
        throw "failed to get attrs";
    }

    attr.c_iflag &= ~( IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON );
    attr.c_oflag &= ~OPOST;
    attr.c_lflag &= ~( ECHO | ECHONL | ICANON | ISIG | IEXTEN );
    attr.c_cflag &= ~( CSIZE | PARENB );
    attr.c_cflag |= CS8;

    cfsetispeed( &attr, B115200 );
    cfsetospeed( &attr, B115200 );

    if( tcsetattr( fileno( f.get() ), TCSANOW, &attr ) ) {
        throw "failed to get attrs";
    }
}

std::shared_ptr<BIO> openSerial( const std::string& name ) {
    std::shared_ptr<FILE> f( fopen( name.c_str(), "r+" ), fclose );

    if( !f ) {
        std::cout << "Opening serial device failed" << std::endl;
        return std::shared_ptr<BIO>();
    }

    setupSerial( f );
    return std::shared_ptr<BIO>(
        BIO_new_fd( fileno( f.get() ), 0 ),
        [f]( BIO* b ) {
            BIO_free(b);
        } );
}

CAConfig::CAConfig( const std::string& name ) : path( "ca/" + name ), name( name ) {
    ca = loadX509FromFile( path + "/ca.crt" );
    caKey = loadPkeyFromFile( path + "/ca.key" );
    ASN1_TIME* tm = X509_get_notBefore( ca );
    notBefore = std::shared_ptr<ASN1_TIME>( tm, ASN1_TIME_free );
}

std::string timeToString( std::shared_ptr<ASN1_TIME> time ) {
    std::shared_ptr<ASN1_GENERALIZEDTIME> gtime( ASN1_TIME_to_generalizedtime( time.get(), 0 ) );
    std::string strdate( ( char* ) ASN1_STRING_data( gtime.get() ), ASN1_STRING_length( gtime.get() ) );

    if( strdate[strdate.size() - 1] != 'Z' ) {
        throw "Got invalid date?";
    }

    return strdate.substr( 0, strdate.size() - 1 );
}

void extractTimes( std::shared_ptr<X509> target,  std::shared_ptr<SignedCertificate> cert ) {
    cert->before = timeToString( std::shared_ptr<ASN1_TIME>( X509_get_notBefore( target.get() ), ASN1_TIME_free ) );
    cert->after = timeToString( std::shared_ptr<ASN1_TIME>( X509_get_notAfter( target.get() ), ASN1_TIME_free ) );
}

bool CAConfig::crlNeedsResign() {
    std::shared_ptr<CRL> crl( new CRL( path + "/ca.crl" ) );
    return crl->needsResign();
}
