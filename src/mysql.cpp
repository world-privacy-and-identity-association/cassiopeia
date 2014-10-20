#include "mysql.h"

#include <stdio.h>

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
        return std::make_pair( err, std::shared_ptr<MYSQL_RES>() );
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
