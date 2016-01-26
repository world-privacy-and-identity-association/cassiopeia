#include "mysql.h"

#include <stdio.h>

#include <iostream>

#include <mysql/errmsg.h>
#include <log/logger.hpp>

//This static variable exists to handle initializing and finalizing the MySQL driver library
std::shared_ptr<int> MySQLJobProvider::lib_ref(
    //Initializer: Store the return code as a pointer to an integer
    new int( mysql_library_init( 0, NULL, NULL ) ),

    //Finalizer: Check the pointer and free resources
    []( int* ref ) {
        if( !ref ) {
            //The library is not initialized
            return;
        }

        if( *ref ) {
            //The library did return an error when initializing
            delete ref;
            return;
        }

        delete ref;

        mysql_library_end();
    } );

MySQLJobProvider::MySQLJobProvider( const std::string& server, const std::string& user, const std::string& password, const std::string& database ) {
    if( !lib_ref || *lib_ref ) {
        throw std::runtime_error("MySQL library not initialized!");
    }

    connect( server, user, password, database );
}

bool MySQLJobProvider::connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database ) {
    disconnect();
    conn = _connect( server, user, password, database );

    return !!conn;
}

std::shared_ptr<MYSQL> MySQLJobProvider::_connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database ) {
    MYSQL* tmp( mysql_init( NULL ) );

    if( !tmp ) {
        return nullptr;
    }

    tmp = mysql_real_connect( tmp, server.c_str(), user.c_str(), password.c_str(), database.c_str(), 3306, NULL, CLIENT_COMPRESS );

    if( !tmp ) {
        return nullptr;
    }

    auto l = lib_ref;
    return std::shared_ptr<MYSQL>(
        tmp,
        [l]( MYSQL * c ) {
            if( c ) {
                mysql_close( c );
            }
        } );
}

bool MySQLJobProvider::disconnect() {
    if( !conn ) {
        return false;
    }

    conn.reset();

    return true;
}

std::pair< int, std::shared_ptr<MYSQL_RES> > MySQLJobProvider::query( const std::string& query ) {
    if( !conn ) {
        return std::make_pair( CR_SERVER_LOST, std::shared_ptr<MYSQL_RES>() );
    }

    int err = mysql_real_query( this->conn.get(), query.c_str(), query.size() );

    if( err ) {
        throw std::runtime_error(std::string( "MySQL error: " ) + mysql_error( this->conn.get() ));
    }

    auto c = conn;
    std::shared_ptr<MYSQL_RES> res(
        mysql_store_result( conn.get() ),
        [c]( MYSQL_RES * r ) {
            if( !r ) {
                return;
            }

            mysql_free_result( r );
        } );

    return std::make_pair( err, res );
}

std::shared_ptr<Job> MySQLJobProvider::fetchJob() {
    std::string q = "SELECT id, targetId, task, executeFrom, executeTo, warning FROM jobs WHERE state='open' AND warning < 3";

    int err = 0;
    std::shared_ptr<MYSQL_RES> res;

    std::tie( err, res ) = query( q );

    if( err ) {
        return nullptr;
    }

    MYSQL_ROW row = mysql_fetch_row( res.get() );

    if( !row ) {
        return nullptr;
    }

    auto job = std::make_shared<Job>();

    unsigned long* l = mysql_fetch_lengths( res.get() );

    if( !l ) {
        return nullptr;
    }

    job->id = std::string( row[0], row[0] + l[0] );
    job->target = std::string( row[1], row[1] + l[1] );
    job->task = std::string( row[2], row[2] + l[2] );
    job->from = std::string( row[3], row[3] + l[3] );
    job->to = std::string( row[4], row[4] + l[4] );
    job->warning = std::string( row[5], row[5] + l[5] );

    logger::notef( "Got a job: (id=%s, target=%s, task=%s, from=%s, to=%s, warnings=%s)", job->id, job->target, job->task, job->from, job->to, job->warning );

    return job;
}

std::string MySQLJobProvider::escape_string( const std::string& target ) {
    if( !conn ) {
        throw std::runtime_error("Not connected!");
    }

    std::string result;

    result.resize( target.size() * 2 );

    long unsigned int len = mysql_real_escape_string( conn.get(), const_cast<char*>( result.data() ), target.c_str(), target.size() );

    result.resize( len );

    return result;
}

void MySQLJobProvider::finishJob( std::shared_ptr<Job> job ) {
    if( !conn ) {
        throw std::runtime_error("Not connected!");
    }

    std::string q = "UPDATE jobs SET state='done' WHERE id='" + this->escape_string( job->id ) + "' LIMIT 1";

    if( query( q ).first ) {
        throw std::runtime_error("No database entry found.");
    }
}

void MySQLJobProvider::failJob( std::shared_ptr<Job> job ) {
    if( !conn ) {
        throw std::runtime_error("Not connected!");
    }

    std::string q = "UPDATE jobs SET warning = warning + 1 WHERE id='" + this->escape_string( job->id ) + "' LIMIT 1";

    if( query( q ).first ) {
        throw std::runtime_error("No database entry found.");
    }
}

std::shared_ptr<TBSCertificate> MySQLJobProvider::fetchTBSCert( std::shared_ptr<Job> job ) {
    auto cert = std::make_shared<TBSCertificate>();
    std::string q = "SELECT md, profile, csr_name, csr_type, keyname FROM certs INNER JOIN profiles ON profiles.id = certs.profile WHERE certs.id='" + this->escape_string( job->target ) + "'";

    int err = 0;

    std::shared_ptr<MYSQL_RES> res;

    std::tie( err, res ) = query( q );

    if( err ) {
        return nullptr;
    }

    MYSQL_ROW row = mysql_fetch_row( res.get() );

    if( !row ) {
        return nullptr;
    }

    unsigned long* l = mysql_fetch_lengths( res.get() );

    if( !l ) {
        return nullptr;
    }

    std::string profileName = std::string( row[4], row[4] + l[4] );

    cert->md = std::string( row[0], row[0] + l[0] );
    std::string profileId = std::string( row[1], row[1] + l[1] );

    while( profileId.size() < 4 ) {
        profileId = "0" + profileId;
    }

    cert->profile = profileId + "-" + profileName;

    cert->csr = std::string( row[2], row[2] + l[2] );
    cert->csr_type = std::string( row[3], row[3] + l[3] );

    cert->SANs = std::vector<std::shared_ptr<SAN>>();

    q = "SELECT contents, type FROM subjectAlternativeNames WHERE certId='" + this->escape_string( job->target ) + "'";
    std::tie( err, res ) = query( q );

    if( err ) {
        std::cout << mysql_error( this->conn.get() );
        return nullptr;
    }

    std::cout << "Fetching SANs" << std::endl;

    while( ( row = mysql_fetch_row( res.get() ) ) ) {
        unsigned long* l = mysql_fetch_lengths( res.get() );

        if( !l ) {
            return nullptr;
        }

        auto nSAN = std::make_shared<SAN>();
        nSAN->content = std::string( row[0], row[0] + l[0] );
        nSAN->type = std::string( row[1], row[1] + l[1] );
        cert->SANs.push_back( nSAN );
    }

    q = "SELECT name, value FROM certAvas WHERE certid='" + this->escape_string( job->target ) + "'";
    std::tie( err, res ) = query( q );

    if( err ) {
        std::cout << mysql_error( this->conn.get() );
        return nullptr;

    }

    while( ( row = mysql_fetch_row( res.get() ) ) ) {
        unsigned long* l = mysql_fetch_lengths( res.get() );

        if( !l ) {
            return nullptr;
        }

        auto nAVA = std::make_shared<AVA>();
        nAVA->name = std::string( row[0], row[0] + l[0] );
        nAVA->value = std::string( row[1], row[1] + l[1] );
        cert->AVAs.push_back( nAVA );
    }

    return cert;
}

void MySQLJobProvider::writeBack( std::shared_ptr<Job> job, std::shared_ptr<SignedCertificate> res ) {
    if( !conn ) {
        throw std::runtime_error("Error while writing back");
    }

    std::string id = "SELECT id FROM cacerts WHERE keyname='" + this->escape_string( res->ca_name ) + "'";

    int err = 0;
    std::shared_ptr<MYSQL_RES> resu;
    std::tie( err, resu ) = query( id );

    if( err ) {
        throw std::runtime_error("Error while looking ca cert id");
    }

    MYSQL_ROW row = mysql_fetch_row( resu.get() );
    unsigned long* l = mysql_fetch_lengths( resu.get() );

    std::string read_id;

    if( !row || !l ) {
        throw std::runtime_error("Error while inserting new ca cert not found");
    } else {
        read_id = std::string( row[0], row[0] + l[0] );
    }

    std::string q = "UPDATE certs SET crt_name='" + this->escape_string( res->crt_name ) + "', serial='" + this->escape_string( res->serial ) + "', caId = '" + this->escape_string( read_id ) + "', created='" + this->escape_string( res->before ) + "', expire='" + this->escape_string( res->after ) + "'  WHERE id='" + this->escape_string( job->target ) + "' LIMIT 1";
    // TODO write more thingies back

    if( query( q ).first ) {
        throw std::runtime_error("Error while writing back");
    }
}

std::pair<std::string, std::string> MySQLJobProvider::getRevocationInfo( std::shared_ptr<Job> job ) {
    std::string q = "SELECT certs.serial, cacerts.keyname FROM certs INNER JOIN cacerts ON certs.caId = cacerts.id WHERE certs.id = '" + this->escape_string( job->target ) + "' ";
    int err = 0;
    std::shared_ptr<MYSQL_RES> resu;
    std::tie( err, resu ) = query( q );

    if( err ) {
        throw std::runtime_error("Error while looking ca cert id");
    }

    MYSQL_ROW row = mysql_fetch_row( resu.get() );
    unsigned long* l = mysql_fetch_lengths( resu.get() );

    if( !row || !l ) {
        throw std::runtime_error("Error while inserting new ca cert");
    }

    return std::pair<std::string, std::string>( std::string( row[0], row[0] + l[0] ), std::string( row[1], row[1] + l[1] ) );
}

void MySQLJobProvider::writeBackRevocation( std::shared_ptr<Job> job, std::string date ) {
    if( query( "UPDATE certs SET revoked = '" + this->escape_string( date ) + "' WHERE id = '" + this->escape_string( job->target ) + "'" ).first ) {
        throw std::runtime_error("Error while writing back revocation");
    }
}
