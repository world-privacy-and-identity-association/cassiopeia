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

int main( int argc, const char* argv[] ) {
    ( void ) argc;
    ( void ) argv;

    std::string path;

    if( DAEMON ) {
        path = "/etc/cacert/cassiopeia/cassiopeia.conf";
    } else {
        path = "config.txt";
    }


    if( parseConfig( path ) != 0 ) {
        return -1;
    }

    return handlermain( argc, argv );
}
