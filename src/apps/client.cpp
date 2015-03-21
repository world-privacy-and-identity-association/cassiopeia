#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <streambuf>
#include <unordered_map>

#include "db/database.h"
#include "db/mysql.h"
#include "crypto/simpleOpensslSigner.h"
#include "crypto/remoteSigner.h"
#include "crypto/sslUtil.h"
#include "util.h"
#include "io/bios.h"
#include "io/slipBio.h"
#include "config.h"

#ifdef NO_DAEMON
#define DAEMON false
#else
#define DAEMON true
#endif

extern std::string keyDir;
extern std::string sqlHost, sqlUser, sqlPass, sqlDB;
extern std::string serialPath;
extern std::unordered_map<std::string, std::shared_ptr<CAConfig>> CAs;

void checkCRLs( std::shared_ptr<Signer> sign ) {
    std::cout << "Signing CRLs" << std::endl;

    for( auto x : CAs ) {
        std::cout << "Checking: " << x.first << std::endl;

        if( !x.second->crlNeedsResign() ) {
            std::cout << "Skipping Resigning CRL: " + x.second->name << std::endl;
            continue;
        }

        std::cout << "Resigning CRL: " + x.second->name << std::endl;

        try {
            std::vector<std::string> serials;
            std::pair<std::shared_ptr<CRL>, std::string> rev = sign->revoke( x.second, serials );
        } catch( const char* c ) {
            std::cout << "Exception: " << c << std::endl;
        }
    }
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
    static_cast<SlipBIO*>( slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( b ) ) );
    std::shared_ptr<RemoteSigner> sign( new RemoteSigner( slip1, generateSSLContext( false ) ) );
    // std::shared_ptr<Signer> sign( new SimpleOpensslSigner() );

    time_t lastCRLCheck = 0;

    while( true ) {
        time_t current;
        time( &current );

        if( lastCRLCheck + 30 * 60 < current ) {
            // todo set good log TODO FIXME
            sign->setLog( std::shared_ptr<std::ostream>(
                &std::cout,
                []( std::ostream * o ) {
                    ( void ) o;
                } ) );
            checkCRLs( sign );
            lastCRLCheck = current;
        }

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
                cert->wishFrom = job->from;
                cert->wishTo = job->to;
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
                std::string fn = writeBackFile( job->target.c_str(), res->certificate, keyDir );

                if( fn.empty() ) {
                    log << "ERROR: Writeback of the certificate failed." << std::endl;
                    jp->failJob( job );
                    continue;
                }

                res->crt_name = fn;
                jp->writeBack( job, res ); //! \FIXME: Check return value
                log << "FINE: signing done." << std::endl;

                if( DAEMON ) {
                    jp->finishJob( job );
                }

                continue;
            } catch( const char* c ) {
                log << "ERROR: " << c << std::endl;
            } catch( std::string& c ) {
                log << "ERROR: " << c << std::endl;
            }

            try {
                jp->failJob( job );
            } catch( const char* c ) {
                log << "ERROR: " << c << std::endl;
            } catch( std::string& c ) {
                log << "ERROR: " << c << std::endl;
            }
        } else if( job->task == "revoke" ) {
            try {
                auto data = jp->getRevocationInfo( job );
                std::vector<std::string> serials;
                serials.push_back( data.first );
                std::pair<std::shared_ptr<CRL>, std::string> rev = sign->revoke( CAs.at( data.second ), serials );
                std::string date = rev.second;
                const unsigned char* pos = ( const unsigned char* ) date.data();
                std::shared_ptr<ASN1_TIME> time( d2i_ASN1_TIME( NULL, &pos, date.size() ), ASN1_TIME_free );

                jp->writeBackRevocation( job, timeToString( time ) );
                jp->finishJob( job );
            } catch( const char* c ) {
                std::cout << "Exception: " << c << std::endl;
            }
        } else {
            log << "Unknown job type" << job->task << std::endl;
            jp->failJob( job );
        }

        if( !DAEMON || once ) {
            return 0;
        }
    }
}
