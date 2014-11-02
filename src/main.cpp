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
#include <iostream>
#include <fstream>
#include <streambuf>

#include "database.h"
#include "mysql.h"
#include "simpleOpensslSigner.h"

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
            sign->sign( cert );
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
