#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <streambuf>

#include "database.h"
#include "mysql.h"
#include "simpleOpensslSigner.h"
#include "util.h"
#include "bios.h"
#include "slipBio.h"
#include "remoteSigner.h"
#include "sslUtil.h"
#include "config.h"

#ifdef NO_DAEMON
#define DAEMON false
#else
#define DAEMON true
#endif

extern std::string keyDir;
extern std::vector<Profile> profiles;
extern std::string sqlHost, sqlUser, sqlPass, sqlDB;

std::string writeBackFile( uint32_t serial, std::string cert ) {
    std::string filename = "keys";
    mkdir( filename.c_str(), 0755 );
    filename += "/crt";
    mkdir( filename.c_str(), 0755 );
    filename += "/" + std::to_string( serial / 1000 );
    mkdir( filename.c_str(), 0755 );
    filename += "/" + std::to_string( serial ) + ".crt";
    writeFile( filename, cert );
    std::cout << "wrote to " << filename << std::endl;
    return filename;
}

int handlermain( int argc, const char* argv[] );

int main( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;
    bool once = false;

    if( argc == 2 && std::string( "--once" ) == std::string( argv[1] ) ) {
        once = true;
    }

    std::string path;

    if( DAEMON ) {
        path = "/etc/cacert/cassiopeia/cassiopeia.conf";
    } else {
        path = "config.txt";
    }

    if( parseConfig( path ) != 0 ) {
        return -1;
    }

    if( argc == 0 ) {
        return handlermain( argc, argv );
    }

    std::shared_ptr<JobProvider> jp( new MySQLJobProvider( sqlHost, sqlUser, sqlPass, sqlDB ) );
    std::shared_ptr<BIO> b = openSerial( "/dev/ttyUSB0" );
    std::shared_ptr<BIO> slip1( BIO_new( toBio<SlipBIO>() ), BIO_free );
    ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( b ) ) );
    std::shared_ptr<RemoteSigner> sign( new RemoteSigner( slip1, generateSSLContext( false ) ) );
    // std::shared_ptr<Signer> sign( new SimpleOpensslSigner() );

    while( true ) {
        std::shared_ptr<Job> job = jp->fetchJob();

        if( !job ) {
            std::cout << "Nothing to work on" << std::endl;
            sleep( 5 );
            continue;
        }

        if( job->task == "sign" ) {
            try {
                std::shared_ptr<TBSCertificate> cert = jp->fetchTBSCert( job );

                if( !cert ) {
                    std::cout << "wasn't able to load CSR" << std::endl;
                    return 2;
                }

                std::cout << "Found a CSR at '" << cert->csr << "' signing" << std::endl;
                cert->csr_content = readFile( cert->csr );
                std::cout << cert->csr_content << " content " << std::endl;

                std::shared_ptr<SignedCertificate> res = sign->sign( cert );
                std::cout << "did it!" << res->certificate << std::endl;
                std::string fn = writeBackFile( atoi( job->target.c_str() ), res->certificate );
                res->crt_name = fn;
                jp->writeBack( job, res );
                std::cout << "wrote back" << std::endl;
            } catch( const char* c ) {
                std::cerr << "ERROR: " << c << std::endl;
                return 2;
            } catch( std::string c ) {
                std::cerr << "ERROR: " << c << std::endl;
                return 2;
            }
        } else {
            std::cout << "Unknown job type" << job->task << std::endl;
        }

        if( DAEMON && !jp->finishJob( job ) ) {
            return 1;
        }

        if( !DAEMON || once ) {
            return 0;
        }
    }
}
