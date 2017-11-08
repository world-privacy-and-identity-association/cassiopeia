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
#include <dirent.h>
#include <crypto/X509.h>

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
        if( !x.second->crlNeedsResign() ) {
            continue;
        }

        logger::notef( "Resigning CRL: %s ...", x.second->name );

        try {
            std::vector<std::string> serials;
            std::pair<std::shared_ptr<CRL>, std::string> rev = sign->revoke( x.second, serials );
        } catch( const std::exception& e ) {
            logger::error( "Exception: ", e.what() );
        }
    }
}

bool pathExists( const std::string& name ) {
    struct stat buffer;
    return stat( name.c_str(), &buffer ) == 0;
}

void signOCSP( std::shared_ptr<Signer> sign, std::string profileName, std::string req, std::string crtName, std::string failName ) {
    auto cert = std::make_shared<TBSCertificate>();
    cert->ocspCA = profileName;
    cert->wishFrom = "now";
    cert->wishTo = "1y";
    cert->md = "sha512";

    logger::note( "INFO: Message Digest: ", cert->md );

    cert->csr_content = req;
    cert->csr_type = "CSR";
    auto nAVA = std::make_shared<AVA>();
    nAVA->name = "CN";
    nAVA->value = "OCSP Responder";
    cert->AVAs.push_back( nAVA );

    std::shared_ptr<SignedCertificate> res = sign->sign( cert );

    if( !res ) {
        writeFile( failName, "failed" );
        logger::error( "OCSP Cert signing failed." );
        return;
    }

    writeFile( crtName, res->certificate );
    logger::notef( "Cert log: %s", res->log );
}

void checkOCSP( std::shared_ptr<Signer> sign ) {
    std::unique_ptr<DIR, std::function<void( DIR * )>> dp( opendir( "ca" ), []( DIR * d ) {
        closedir( d );
    } );

    // When opendir fails and returns 0 the unique_ptr will be considered unintialized and will not call closedir.
    // Even if closedir would be called, according to POSIX it MAY handle nullptr properly (for glibc it does).
    if( !dp ) {
        logger::error( "CA directory not found" );
        return;
    }

    struct dirent *ep;

    while( ( ep = readdir( dp.get() ) ) ) {
        if( ep->d_name[0] == '.' ) {
            continue;
        }

        std::string profileName( ep->d_name );
        std::string csr = "ca/" + profileName + "/ocsp.csr";

        if( ! pathExists( csr ) ) {
            continue;
        }

        std::string crtName = "ca/" + profileName + "/ocsp.crt";

        if( pathExists( crtName ) ) {
            continue;
        }

        std::string failName = "ca/" + profileName + "/ocsp.fail";

        if( pathExists( failName ) ) {
            continue;
        }

        logger::notef( "Discovered OCSP CSR that needs action: %s", csr );
        std::string req = readFile( csr );
        std::shared_ptr<X509Req> parsed = X509Req::parseCSR( req );

        if( parsed->verify() <= 0 ) {
            logger::errorf( "Invalid CSR for %s", profileName );
            continue;
        }

        signOCSP( sign, profileName, req, crtName, failName );
    }
}


int main( int argc, const char *argv[] ) {
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
    static_cast<SlipBIO *>( slip1->ptr )->setTarget( std::make_shared<OpensslBIOWrapper>( b ), false );
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
                auto ostreamFree = []( std::ostream * o ) {
                    ( void ) o;
                };
                sign->setLog( std::shared_ptr<std::ostream>( &std::cout, ostreamFree ) );
                checkCRLs( sign );
                lastCRLCheck = current;
            }

            checkOCSP( sign );

            std::shared_ptr<Job> job;

            try {
                job = jp->fetchJob();
            } catch( std::exception& e ) {
                logger::errorf( "Exception while fetchJob: %s", e.what() );
            }

            if( !job ) {
                sleep( 5 );
                continue;
            }

            logger::logger_set log_set( {logger::log_target( job->log, logger::level::debug )}, logger::auto_register::on );

            logger::note( "TASK ID: ", job->id );
            logger::note( "TRY:     ", job->attempt );
            logger::note( "TARGET:  ", job->target );
            logger::note( "TASK:    ", job->task );

            if( job->task == "sign" ) {
                try {
                    std::shared_ptr<TBSCertificate> cert = jp->fetchTBSCert( job );

                    if( !cert ) {
                        logger::error( "Unable to load CSR" );
                        jp->failJob( job );
                        continue;
                    }

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

                    logger::note( "FINE: CSR content:\n", cert->csr_content );

                    std::shared_ptr<SignedCertificate> res = sign->sign( cert );

                    if( !res ) {
                        logger::error( "ERROR: The signer failed. No certificate was returned." );
                        jp->failJob( job );
                        continue;
                    }

                    logger::note( "FINE: CERTIFICATE LOG:\n", res->log,
                                  "FINE: CERTIFICATE:\n", res->certificate );

                    jp->writeBack( job, res ); //! \FIXME: Check return value
                    logger::note( "FINE: signing done." );

                    if( DAEMON ) {
                        jp->finishJob( job );
                    }
                } catch( std::exception& c ) {
                    jp->failJob( job );
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
                    const unsigned char *pos = ( const unsigned char * ) date.data();
                    std::shared_ptr<ASN1_TIME> time( d2i_ASN1_TIME( NULL, &pos, date.size() ), ASN1_TIME_free );

                    jp->writeBackRevocation( job, timeToString( time ) );
                    jp->finishJob( job );
                    continue;
                } catch( const std::exception& c ) {
                    jp->failJob( job );
                    logger::error( "Exception: ", c.what() );
                }
            } else {
                logger::errorf( "Unknown job type (\"%s\")", job->task );
                jp->failJob( job );
            }

            if( !DAEMON || once ) {
                return 0;
            }
        } catch( std::exception& e ) {
            logger::errorf( "std::exception in mainloop: %s", e.what() );
        }

    }
}
