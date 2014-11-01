#include "mysql.h"

#include <stdio.h>

#include <iostream>

#include <mysql/errmsg.h>

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
        throw "MySQL library not initialized!";
    }

    connect( server, user, password, database );
}

MySQLJobProvider::~MySQLJobProvider() {
    disconnect();
}

bool MySQLJobProvider::connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database ) {
    if( conn ) {
        if( !disconnect() ) {
            return false;
        }

        conn.reset();
    }

    conn = _connect( server, user, password, database );

    return !!conn;
}

std::shared_ptr<MYSQL> MySQLJobProvider::_connect( const std::string& server, const std::string& user, const std::string& password, const std::string& database ) {
    MYSQL* tmp( mysql_init( NULL ) );

    if( !tmp ) {
        return std::shared_ptr<MYSQL>();
    }

    tmp = mysql_real_connect( tmp, server.c_str(), user.c_str(), password.c_str(), database.c_str(), 3306, NULL, CLIENT_COMPRESS );

    if( !tmp ) {
        return std::shared_ptr<MYSQL>();
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
        throw std::string( "MySQL error: " ) + mysql_error( this->conn.get() );
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
    std::string q = "SELECT id, targetId, task, executeFrom, executeTo FROM jobs WHERE state='open'";

    int err = 0;
    std::shared_ptr<MYSQL_RES> res;

    std::tie( err, res ) = query( q );

    if( err ) {
        return std::shared_ptr<Job>();
    }

    unsigned int num = mysql_num_fields( res.get() );

    MYSQL_ROW row = mysql_fetch_row( res.get() );

    if( !row ) {
        return std::shared_ptr<Job>();
    }

    std::shared_ptr<Job> job( new Job() );

    unsigned long* l = mysql_fetch_lengths( res.get() );

    if( !l ) {
        return std::shared_ptr<Job>();
    }

    job->id = std::string( row[0], row[0] + l[0] );
    job->target = std::string( row[1], row[1] + l[1] );
    job->task = std::string( row[2], row[2] + l[2] );
    job->from = std::string( row[3], row[3] + l[3] );
    job->to = std::string( row[4], row[4] + l[4] );

    for( unsigned int i = 0; i < num; i++ ) {
        printf( "[%.*s] ", ( int ) l[i], row[i] ? row[i] : "NULL" );
    }

    printf( "\n" );

    return job;
}

std::string MySQLJobProvider::escape_string( const std::string& target ) {
    if( !conn ) {
        throw "Not connected!";
    }

    std::string result;

    result.resize( target.size() * 2 );

    long unsigned int len = mysql_real_escape_string( conn.get(), const_cast<char*>( result.data() ), target.c_str(), target.size() );

    result.resize( len );

    return result;
}

bool MySQLJobProvider::finishJob( std::shared_ptr<Job> job ) {
    if( !conn ) {
        return false;
    }

    std::string q = "UPDATE jobs SET state='done' WHERE id='" + this->escape_string( job->id ) + "' LIMIT 1";

    if( query( q ).first ) {
        return false;
    }

    return true;
}

std::shared_ptr<TBSCertificate> MySQLJobProvider::fetchTBSCert( std::shared_ptr<Job> job ) {
    std::shared_ptr<TBSCertificate> cert = std::shared_ptr<TBSCertificate>( new TBSCertificate() );
    std::string q = "SELECT md, profile, csr_name, csr_type FROM certs WHERE id='" + this->escape_string( job->target ) + "'";

    int err = 0;

    std::shared_ptr<MYSQL_RES> res;

    std::tie( err, res ) = query( q );

    if( err ) {
        return std::shared_ptr<TBSCertificate>();
    }

    MYSQL_ROW row = mysql_fetch_row( res.get() );

    if( !row ) {
        return std::shared_ptr<TBSCertificate>();
    }

    unsigned long* l = mysql_fetch_lengths( res.get() );

    if( !l ) {
        return std::shared_ptr<TBSCertificate>();
    }

    cert->md = std::string( row[0], row[0] + l[0] );
    cert->profile = std::string( row[1], row[1] + l[1] );
    cert->csr = std::string( row[2], row[2] + l[2] );
    cert->csr_type = std::string( row[3], row[3] + l[3] );

    cert->SANs = std::vector<std::shared_ptr<SAN>>();

    q = "SELECT contents, type FROM subjectAlternativeNames WHERE certId='" + this->escape_string( job->target ) + "'";
    std::tie( err, res ) = query( q );

    if( err ) {
        std::cout << mysql_error( this->conn.get() );
        return std::shared_ptr<TBSCertificate>();
    }

    std::cout << "Fetching SANs" << std::endl;

    while( ( row = mysql_fetch_row( res.get() ) ) ) {
        unsigned long* l = mysql_fetch_lengths( res.get() );

        if( !l ) {
            return std::shared_ptr<TBSCertificate>();
        }

        std::shared_ptr<SAN> nSAN = std::shared_ptr<SAN>( new SAN() );
        nSAN->content = std::string( row[0], row[0] + l[0] );
        nSAN->type = std::string( row[1], row[1] + l[1] );
        cert->SANs.push_back( nSAN );
    }

    q = "SELECT name, value FROM certAvas WHERE certid='" + this->escape_string( job->target ) + "'";
    std::tie( err, res ) = query( q );

    if( err ) {
        std::cout << mysql_error( this->conn.get() );
        return std::shared_ptr<TBSCertificate>();

    }

    while( ( row = mysql_fetch_row( res.get() ) ) ) {
        unsigned long* l = mysql_fetch_lengths( res.get() );

        if( !l ) {
            return std::shared_ptr<TBSCertificate>();
        }

        std::shared_ptr<AVA> nAVA = std::shared_ptr<AVA>( new AVA() );
        nAVA->name = std::string( row[0], row[0] + l[0] );
        nAVA->value = std::string( row[1], row[1] + l[1] );
        cert->AVAs.push_back( nAVA );
    }

    return cert;
}

void MySQLJobProvider::writeBack( std::shared_ptr<Job> job, std::shared_ptr<SignedCertificate> res ) {
    if( !conn ) {
        throw "Error while writing back";
    }

    std::string q = "UPDATE certs SET crt_name='" + this->escape_string( res->crt_name ) + "', serial='" + this->escape_string( res->serial ) + "', created=NOW() WHERE id='" + this->escape_string( job->target ) + "' LIMIT 1";

    // TODO write more thingies back

    if( query( q ).first ) {
        throw "Error while writing back";
    }
}
