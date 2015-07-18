#include <iostream>
#include <fstream>
#include <streambuf>
#include <stdexcept>

#include "db/database.h"
#include "db/mysql.h"
#include "crypto/simpleOpensslSigner.h"
#include "crypto/remoteSigner.h"
#include "crypto/sslUtil.h"
#include "io/bios.h"
#include "io/slipBio.h"
#include "io/recordHandler.h"
#include "log/logger.hpp"
#include "util.h"
#include "config.h"

#ifdef NO_DAEMON
#define DAEMON false
#else
#define DAEMON true
#endif

extern std::string serialPath;

int main( int argc, const char* argv[] ) try {
    ( void ) argc;
    ( void ) argv;

    std::string path;

#ifdef NDEBUG
    path = "/etc/cacert/cassiopeia/cassiopeia.conf";
#else
    path = "config.txt";
#endif

    if( parseConfig( path ) != 0 ) {
        logger::fatal( "Could not parse configuration file." );
        return -1;
    }

    std::shared_ptr<int> ssl_lib = ssl_lib_ref;

    if( serialPath == "" ) {
        logger::fatal( "Error: No device for the serial connection was given." );
        return -1;
    }

    std::shared_ptr<BIO> conn = openSerial( serialPath );
    std::shared_ptr<BIO> slip1( BIO_new( toBio<SlipBIO>() ), BIO_free );
    static_cast<SlipBIO*>( slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( conn ) ) );

    DefaultRecordHandler* dh = new DefaultRecordHandler( std::shared_ptr<Signer>( new SimpleOpensslSigner( ) ), slip1 );

    while( true ) {
        try {
            dh->handle();
            //} catch( const std::exception &ch ) {
            //std::cout << "Real exception: " << typeid(ch).name() << ", " << ch.what() << std::endl;
        } catch( const std::string& ch ) {
            logger::error( "Exception: ", ch );
        } catch( char const* ch ) {
            logger::error( "Exception: ", ch );
        }
    }

    return -1;

} catch( std::exception& e ) {
    logger::fatalf( "Fatal Error: %s!\n", e.what() );
    return -1;
} catch( ... ) {
    logger::fatal( "Fatal Error: Unknown Exception!\n" );
    return -1;
}
