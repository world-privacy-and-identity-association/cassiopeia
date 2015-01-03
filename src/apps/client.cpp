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
extern std::string serialPath;

std::string writeBackFile( uint32_t serial, std::string cert ) {
    std::string filename = keyDir;
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

int main( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;
    bool once = false;

    if( argc == 2 && std::string( "--once" ) == std::string( argv[1] ) ) {
        once = true;
    }

    std::string path;

#ifdef NDEBUG
    path = "/etc/cacert/cassiopeia/cassiopeia.conf";
#else
    path = "config.txt";
#endif

    if( parseConfig( path ) != 0 ) {
        return -1;
    }

    if( serialPath == "" ) {
        std::cout << "Error: no serial device is given" << std::endl;
        return -1;
    }

    std::shared_ptr<JobProvider> jp( new MySQLJobProvider( sqlHost, sqlUser, sqlPass, sqlDB ) );
    std::shared_ptr<BIO> b = openSerial( serialPath );
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

        std::ofstream* logP = new std::ofstream( std::string( "logs/" ) + job->id + std::string( "_" ) + job->warning + std::string( ".log" ) );
        std::shared_ptr<std::ofstream> logPtr(
            logP,
            []( std::ofstream * ptr ) {
                ( *ptr ).close();
                delete ptr;
            } );
        std::ofstream& log = *logP;

        sign->setLog( logPtr );
        log << "TASK ID: " << job->id << std::endl;
        log << "TRY: " << job->warning << std::endl;
        log << "TARGET: " << job->target << std::endl;
        log << "TASK: " << job->task << std::endl << std::endl;

        if( job->task == "sign" ) {
            try {
                std::shared_ptr<TBSCertificate> cert = jp->fetchTBSCert( job );
                log << "INFO: message digest: " << cert->md << std::endl;
                log << "INFO: profile id: " << cert->profile << std::endl;

                for( auto& SAN : cert->SANs ) {
                    log << "INFO: SAN " << SAN->type << ": " << SAN->content;
                }

                for( auto& AVA : cert->AVAs ) {
                    log << "INFO: AVA " << AVA->name << ": " << AVA->value;
                }

                if( !cert ) {
                    std::cout << "wasn't able to load CSR" << std::endl;
                    jp->failJob( job );
                    continue;
                }

                log << "FINE: Found the CSR at '" << cert->csr << "'" << std::endl;
                cert->csr_content = readFile( keyDir + "/../" + cert->csr );
                log << "FINE: CSR is " << std::endl << cert->csr_content << std::endl;

                std::shared_ptr<SignedCertificate> res = sign->sign( cert );

                if( !res ) {
                    log << "ERROR: The signer failed. There was no certificate." << std::endl;
                    jp->failJob( job );
                    continue;
                }

                log << "FINE: CERTIFICATE LOG: " << res->log << std::endl;
                log << "FINE: CERTIFICATE:" << std::endl << res->certificate << std::endl;
                std::string fn = writeBackFile( atoi( job->target.c_str() ), res->certificate );
                res->crt_name = fn;
                jp->writeBack( job, res );
                log << "FINE: signing done." << std::endl;

                if( DAEMON ) {
                    jp->finishJob( job );
                }

                continue;
            } catch( const char* c ) {
                log << "ERROR: " << c << std::endl;
            } catch( std::string c ) {
                log << "ERROR: " << c << std::endl;
            }

            try {
                jp->failJob( job );
            } catch( const char* c ) {
                log << "ERROR: " << c << std::endl;
            } catch( std::string c ) {
                log << "ERROR: " << c << std::endl;
            }
        } else {
            log << "Unknown job type" << job->task << std::endl;
        }

        if( !DAEMON || once ) {
            return 0;
        }
    }
}
