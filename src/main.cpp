/*
    Cassiopeia - CAcert signing module
    Copyright (C) 2014  CAcert Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <streambuf>

#include "database.h"
#include "mysql.h"
#include "simpleOpensslSigner.h"

#ifdef NO_DAEMON
#define DAEMON false
#else
#define DAEMON true
#endif

std::string keyDir;
std::vector<Profile> profiles;
std::string sqlHost, sqlUser, sqlPass, sqlDB;

std::string writeBackFile( uint32_t serial, std::string cert ) {
    std::string filename = "keys";
    mkdir( filename.c_str(), 0755 );
    filename += "/crt";
    mkdir( filename.c_str(), 0755 );
    filename += "/" + std::to_string( serial / 1000 );
    mkdir( filename.c_str(), 0755 );
    filename += "/" + std::to_string( serial ) + ".crt";
    std::ofstream file;
    file.open( filename.c_str() );
    file << cert.c_str();
    file.close();
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

    std::ifstream config;
    config.open( "config.txt" );

    if( !config.is_open() ) {
        std::cerr << "config missing" << std::endl;
        return 1;
    }

    std::string line1;

    while( config >> line1 ) {
        if( line1[0] == '#' ) {
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
        }

        if( key.compare( 0, 8, "profile." ) == 0 ) {
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
            } else {
                std::cout << "invalid line: " << line1 << std::endl;
                continue;
            }
        }
    }

    std::cout << profiles.size() << " profiles loaded." << std::endl;

    if( keyDir == "" ) {
        std::cerr << "Missing config property key.directory" << std::endl;
        return -1;
    }

    config.close();

    std::shared_ptr<JobProvider> jp( new MySQLJobProvider( sqlHost, sqlUser, sqlPass, sqlDB ) );
    std::shared_ptr<Signer> sign( new SimpleOpensslSigner() );

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
                std::ifstream t( cert->csr );
                cert->csr_content = std::string( std::istreambuf_iterator<char>( t ), std::istreambuf_iterator<char>() );

                std::shared_ptr<SignedCertificate> res = sign->sign( cert );
                std::string fn = writeBackFile( atoi( job->target.c_str() ), res->certificate );
                res->crt_name = fn;
                jp->writeBack( job, res );
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
