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

#include <iostream>
#include <fstream>
#include <streambuf>

#include "database.h"
#include "mysql.h"
#include "simpleOpensslSigner.h"

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
    return filename;
}

int main( int argc, const char* argv[] ) {
    if( argc < 2 ) {
        std::cout << argv[0] << " password" << std::endl;
        return 1;
    }

    std::shared_ptr<JobProvider> jp( new MySQLJobProvider( "localhost", "cacert", argv[1], "cacert" ) );
    std::shared_ptr<Signer> sign( new SimpleOpensslSigner() );
    std::shared_ptr<Job> job = jp->fetchJob();

    if( !job ) {
        std::cout << "Nothing to work on" << std::endl;
        return 2;
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
            std::string fn = writeBackFile( res->serial, res->certificate );
            res->crt_name = fn;
            jp->writeBack( job, res );
        } catch( const char* c ) {
            std::cerr << c << std::endl;
            return 2;
        }
    }

    if( !jp->finishJob( job ) ) {
        return 1;
    }

    return 0;
}
