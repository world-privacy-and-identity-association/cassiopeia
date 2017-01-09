#include "util.h"

#include <sys/stat.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <time.h>
#include <stdexcept>

void writeFile( const std::string& name, const std::string& content ) {
    std::ofstream file( name );
    file << content;

    //! \FIXME: Error checking
}

std::string readFile( const std::string& name ) {
    std::ifstream t( name );
    std::string res = std::string( std::istreambuf_iterator<char>( t ), std::istreambuf_iterator<char>() );

    return res;
}

std::string writeBackFile( const std::string& serial, const std::string& cert, const std::string& keydir ) {
    errno = 0;

    std::string filename = keydir;

    if( 0 != mkdir( filename.c_str(), 0755 ) ) {
        if( EEXIST != errno ) {
            throw std::runtime_error("Storage location could not be determined");
        }

        //! \FIXME: Check this is a directory
    }

    filename += "/crt";

    if( 0 != mkdir( filename.c_str(), 0755 ) ) {
        if( EEXIST != errno ) {
            return "";
        }

        //! \FIXME: Check this is a directory
    }

    std::string first;

    if( serial.length() < 3 ) {
        first = "0";
    } else {
        first = serial.substr( 0, serial.length() - 3 );
    }

    filename += "/" + first;

    if( 0 != mkdir( filename.c_str(), 0755 ) ) {
        if( EEXIST != errno ) {
            return "";
        }

        //! \FIXME: Check this is a directory
    }

    filename += "/" + serial + ".crt";
    writeFile( filename, cert );

    return filename;
}

bool isDigit( char c ) {
    return ( c >= '0' ) && ( c <= '9' );
}

std::pair<bool, time_t> parseDate( const std::string& date ) {
    if( date.size() != 10 || date[4] != '-' || date[7] != '-' ) {
        return std::pair<bool, time_t>( false, 0 );
    }

    if( !isDigit( date[0] )
            || !isDigit( date[1] )
            || !isDigit( date[2] )
            || !isDigit( date[3] )
            || !isDigit( date[5] )
            || !isDigit( date[6] )
            || !isDigit( date[8] )
            || !isDigit( date[9] ) ) {
        return std::pair<bool, time_t>( false, 0 );
    }

    std::tm t = {};
    t.tm_sec = 0;
    t.tm_min = 0;
    t.tm_hour = 0;
    t.tm_mday = std::stoi( date.substr( 8, 2 ) );
    t.tm_mon = std::stoi( date.substr( 5, 2 ) ) - 1;
    t.tm_year = std::stoi( date.substr( 0, 4 ) ) - 1900;

    setenv( "TZ", "UTC", 1 );
    tzset();
    std::time_t res = mktime( &t );
    char check[11];
    std::size_t siz = strftime( check, 11, "%Y-%m-%d", &t );

    if( siz != 10 ) {
        return std::pair<bool, time_t>( false, 0 ); // NO-COVERAGE (by contract of strftime)
    }

    std::string checkS( check, siz );

    if( checkS != date ) {
        return { false, 0 };
    }

    return std::pair<bool, time_t>( true, res );
}

std::pair<bool, time_t> addMonths( std::time_t t, int32_t count ) {
    std::tm* parsed = gmtime( &t );

    if( !parsed || count <= 0 || count > 24 ) { // FIXED MAX-Validity-Length
        return std::pair<bool, time_t>( false, 0 );
    }

    parsed->tm_mon += count;
    int oldday = parsed->tm_mday;
    setenv( "TZ", "UTC", 1 );
    tzset();
    std::time_t res = mktime( parsed );

    if( parsed->tm_mday != oldday ) {
        parsed->tm_mday = 0;
        res = mktime( parsed );
    }

    return std::pair<bool, time_t>( true, res );
}

std::pair<bool, time_t> parseMonthInterval( std::time_t t, const std::string& date ) {
    if( date[date.size() - 1] != 'm' ) {
        return  std::pair<bool, time_t>( false, 0 );
    }

    try {
        size_t end = 0;
        int num = std::stoi( date.substr( 0, date.size() - 1 ) , &end );

        if( end != date.size() - 1 ) {
            return  std::pair<bool, time_t>( false, 0 );
        }

        return addMonths( t, num );
    } catch( const std::invalid_argument& a ) {
        return std::pair<bool, time_t>( false, 0 );
    } catch( const std::out_of_range& a ) {
        return std::pair<bool, time_t>( false, 0 );
    }
}

std::pair<bool, time_t> parseYearInterval( std::time_t t, const std::string& date ) {
    if( date[date.size() - 1] != 'y' ) {
        return  std::pair<bool, time_t>( false, 0 );
    }

    try {
        size_t end = 0;
        int num = std::stoi( date.substr( 0, date.size() - 1 ), &end );

        if( end != date.size() - 1 ) {
            return  std::pair<bool, time_t>( false, 0 );
        }

        return addMonths( t, num * 12 );
    } catch( std::invalid_argument& a ) {
        return std::pair<bool, time_t>( false, 0 );
    } catch( std::out_of_range& a ) {
        return std::pair<bool, time_t>( false, 0 );
    }
}

std::unique_ptr<std::ofstream> openLogfile( const std::string &name ) {
    struct stat buffer;
    std::string tname = name;
    int ctr = 2;

    while( stat( tname.c_str(), &buffer ) == 0 ) {
        tname = name + "_" + std::to_string( ctr++ );
    }

    auto res = std::make_unique<std::ofstream>( tname );

    if( ! res->good() ) {
        throw std::runtime_error( std::string("Failed to open file for logging: " ) + name );
    }

    return res;
}

std::string timestamp(){
    time_t c_time;
    if( time( &c_time ) == -1 ) {
        throw std::runtime_error( "Error while fetching time?" );
    }
    return std::to_string( c_time );
}
