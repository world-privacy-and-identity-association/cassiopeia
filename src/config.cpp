#include <iostream>
#include <vector>
#include <fstream>

#include "sslUtil.h"

std::string keyDir;
std::vector<Profile> profiles;
std::string sqlHost, sqlUser, sqlPass, sqlDB;
std::string serialPath;

int parseConfig( std::string path ) {
    std::ifstream config;
    config.open( path );

    if( !config.is_open() ) {
        std::cerr << "config missing" << std::endl;
        return 1;
    }

    std::string line1;

    while( std::getline( config, line1 ) ) {
        if( line1[0] == '#' || line1.size() == 0 ) {
            continue;
        }

        int splitter = line1.find( "=" );

        if( splitter == -1 ) {
            std::cerr << "Ignoring malformed config line: " << line1 << std::endl;
            continue;
        }

        std::string key = line1.substr( 0, splitter );
        std::string value = line1.substr( splitter + 1 );

        if( key == "key.directory" ) {
            keyDir = value;
            continue;
        } else if( key == "sql.host" ) {
            sqlHost = value;
        } else if( key == "sql.user" ) {
            sqlUser = value;
        } else if( key == "sql.password" ) {
            sqlPass = value;
        } else if( key == "sql.database" ) {
            sqlDB = value;
        } else if( key == "serialPath" ) {
            serialPath = value;
        } else  if( key.compare( 0, 8, "profile." ) == 0 ) {
            int numE = key.find( ".", 9 );

            if( numE == 0 ) {
                std::cout << "invalid line: " << line1 << std::endl;
                continue;
            }

            unsigned int i = atoi( key.substr( 8, numE - 8 ).c_str() );
            std::string rest = key.substr( numE + 1 );

            if( i + 1 > profiles.size() ) {
                profiles.resize( i + 1 );
            }

            if( rest == "key" ) {
                profiles[i].key = value;
            } else if( rest == "cert" ) {
                profiles[i].cert = value;
            } else if( rest == "ku" ) {
                profiles[i].ku = value;
            } else if( rest == "eku" ) {
                profiles[i].eku = value;
            } else {
                std::cout << "invalid line: " << line1 << std::endl;
                continue;
            }
        }
    }

    for( auto& prof : profiles ) {
        if( prof.cert != "" && prof.key != "" ) {
            std::cout << "Loading profile... " << std::endl;
            prof.ca = loadX509FromFile( prof.cert );
            prof.caKey = loadPkeyFromFile( prof.key );
        }
    }

    std::cout << profiles.size() << " profiles loaded." << std::endl;

    if( keyDir == "" ) {
        std::cerr << "Missing config property key.directory" << std::endl;
        return -1;
    }

    config.close();
    return 0;
}
