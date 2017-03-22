#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <streambuf>
#include <unordered_map>

#include "db/database.h"
#include "db/psql.h"
#include "crypto/simpleOpensslSigner.h"
#include "crypto/remoteSigner.h"
#include "crypto/sslUtil.h"
#include "log/logger.hpp"
#include "util.h"
#include "io/bios.h"
#include "io/slipBio.h"
#include "config.h"
#include <internal/bio.h>

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

    logger::note( "Signing CRLs" );

    for( auto& x : CAs ) {
        logger::notef( "Checking: %s ...", x.first );

        if( !x.second->crlNeedsResign() ) {
            logger::warnf( "Skipping Resigning CRL: %s ...", x.second->name );
            continue;
        }

        logger::notef( "Resigning CRL: %s ...", x.second->name );

        try {
            std::vector<std::string> serials;
            std::pair<std::shared_ptr<CRL>, std::string> rev = sign->revoke( x.second, serials );
        } catch( const std::exception &e ) {
            logger::error( "Exception: ", e.what() );
        }
    }
}

int main( int argc, const char* argv[] ) {
    bool once = false;
    bool resetOnly = false;

    if( argc == 2 && std::string( "--once" ) == argv[1] ) {
        once = true;
    }

    if( argc == 2 && std::string( "--reset" ) == argv[1] ) {
        resetOnly = true;
    }

    std::string path;

#ifdef NDEBUG
    path = "/etc/wpia/cassiopeia/cassiopeia.conf";
#else
    path = "config.txt";
#endif

    if( parseConfig( path ) != 0 ) {
        logger::fatal( "Error: Could not parse the configuration file." );
        return -1;
    }

    if( serialPath == "" ) {
        logger::fatal( "Error: no serial device is given!" );
        return -1;
    }

    std::shared_ptr<JobProvider> jp = std::make_shared<PostgresJobProvider>( sqlHost, sqlUser, sqlPass, sqlDB );
    std::shared_ptr<BIO> b = openSerial( serialPath );
    std::shared_ptr<BIO_METHOD> m( toBio<SlipBIO>(), BIO_meth_free );
    std::shared_ptr<BIO> slip1( BIO_new( m.get() ), BIO_free );
    static_cast<SlipBIO*>( slip1->ptr )->setTarget( std::make_shared<OpensslBIOWrapper>( b ), false );
    auto sign = std::make_shared<RemoteSigner>( slip1, generateSSLContext( false ) );
    // std::shared_ptr<Signer> sign( new SimpleOpensslSigner() );

    if( resetOnly ) {
        std::cout << "Doing BIO reset" << std::endl;
        int result = BIO_reset( slip1.get() );
        std::cout << "Did BIO reset, result " << result << ", exiting." << std::endl;
        return result;
    }

    time_t lastCRLCheck = 0;

    while( true ) {
        try {
            time_t current;
            time( &current );

            if( lastCRLCheck + 30 * 60 < current ) {
                // todo set good log TODO FIXME
                sign->setLog( std::shared_ptr<std::ostream>(
                    &std::cout,
                    []( std::ostream* o ) {
                        ( void ) o;
                    } ) );
                checkCRLs( sign );
                lastCRLCheck = current;
            }

            std::shared_ptr<Job> job;

            try {
                job = jp->fetchJob();
            } catch ( std::exception &e ){
                logger::errorf( "Exception while fetchJob: %s", e.what() );
            }

            if( !job ) {
                sleep( 5 );
                continue;
            }

            std::shared_ptr<std::ofstream> logPtr = openLogfile( std::string( "logs/" ) + job->id + std::string( "_" ) + job->warning + std::string( ".log" ) );

            logger::logger_set log_set( {logger::log_target( *logPtr, logger::level::debug )}, logger::auto_register::on );

            logger::note( "TASK ID: ", job->id );
            logger::note( "TRY:     ", job->warning );
            logger::note( "TARGET:  ", job->target );
            logger::note( "TASK:    ", job->task );

            if( job->task == "sign" ) {
                try {
                    std::shared_ptr<TBSCertificate> cert = jp->fetchTBSCert( job );
                    cert->wishFrom = job->from;
                    cert->wishTo = job->to;
                    logger::note( "INFO: Message Digest: ", cert->md );
                    logger::note( "INFO: Profile ID: ", cert->profile );

                    for( auto& SAN : cert->SANs ) {
                        logger::notef( "INFO: SAN %s: %s", SAN->type, SAN->content );
                    }

                    for( auto& AVA : cert->AVAs ) {
                        logger::notef( "INFO: AVA %s: %s", AVA->name, AVA->value );
                    }

                    if( !cert ) {
                        logger::error( "Unable to load CSR" );
                        jp->failJob( job );
                        continue;
                    }

                    logger::notef( "FINE: Found the CSR at '%s'", cert->csr );
                    cert->csr_content = readFile( keyDir + "/../" + cert->csr );
                    logger::note( "FINE: CSR content:\n", cert->csr_content );

                    std::shared_ptr<SignedCertificate> res = sign->sign( cert );

                    if( !res ) {
                        logger::error( "ERROR: The signer failed. No certificate was returned." );
                        jp->failJob( job );
                        continue;
                    }

                    logger::note( "FINE: CERTIFICATE LOG:\n", res->log,
                                  "FINE: CERTIFICATE:\n", res->certificate );

                    std::string fn = writeBackFile( job->target.c_str(), res->certificate, keyDir );

                    if( fn.empty() ) {
                        logger::error( "ERROR: Writeback of the certificate failed." );
                        jp->failJob( job );
                        continue;
                    }

                    res->crt_name = fn;
                    jp->writeBack( job, res ); //! \FIXME: Check return value
                    logger::note( "FINE: signing done." );

                    if( DAEMON ) {
                        jp->finishJob( job );
                    }

                    continue;
                } catch( std::exception& c ) {
                    logger::error( "ERROR: ", c.what() );
                }

                try {
                    jp->failJob( job );
                } catch( std::exception& c ) {
                    logger::error( "ERROR: ", c.what() );
                }
            } else if( job->task == "revoke" ) {
                try {
                    logger::note( "revoking" );
                    auto data = jp->getRevocationInfo( job );
                    std::vector<std::string> serials;
                    serials.push_back( data.first );
                    logger::note( "revoking" );
                    std::pair<std::shared_ptr<CRL>, std::string> rev = sign->revoke( CAs.at( data.second ), serials );
                    std::string date = rev.second;
                    const unsigned char* pos = ( const unsigned char* ) date.data();
                    std::shared_ptr<ASN1_TIME> time( d2i_ASN1_TIME( NULL, &pos, date.size() ), ASN1_TIME_free );

                    jp->writeBackRevocation( job, timeToString( time ) );
                    jp->finishJob( job );
                } catch( const std::exception& c ) {
                    logger::error( "Exception: ", c.what() );
                }
            } else {
                logger::errorf( "Unknown job type (\"%s\")", job->task );
                jp->failJob( job );
            }

            if( !DAEMON || once ) {
                return 0;
            }
        } catch ( std::exception &e ){
            logger::errorf( "std::exception in mainloop: %s", e.what() );
        }

    }
}
