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
#include "recordHandler.h"

#ifdef NO_DAEMON
#define DAEMON false
#else
#define DAEMON true
#endif

int handlermain( int argc, const char* argv[] );

extern std::string serialPath;
extern std::vector<Profile> profiles;

int main( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;

    std::string path;

#ifdef NDEBUG
    path = "/etc/cacert/cassiopeia/cassiopeia.conf";
#else
    path = "config.txt";
#endif

    if( parseConfig( path ) != 0 ) {
        return -1;
    }

    std::shared_ptr<int> ssl_lib = ssl_lib_ref;

    if( serialPath == "" ) {
        std::cout << "Error: no serial device is given" << std::endl;
        return -1;
    }

    std::shared_ptr<BIO> conn = openSerial( serialPath );
    std::shared_ptr<BIO> slip1( BIO_new( toBio<SlipBIO>() ), BIO_free );
    ( ( SlipBIO* )slip1->ptr )->setTarget( std::shared_ptr<OpensslBIO>( new OpensslBIOWrapper( conn ) ) );

    try {
        DefaultRecordHandler* dh = new DefaultRecordHandler( std::shared_ptr<Signer>( new SimpleOpensslSigner( profiles[5] ) ), slip1 );

        while( true ) {
            dh->handle();
        }
    } catch( char const* ch ) {
        std::cout << "Exception: " << ch << std::endl;
    }

    return -1;
}
