#include "util.h"

#include <sys/stat.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <time.h>
#include <stdexcept>

void writeFile( const std::string& name, const std::string& content ) {
    std::ofstream file;

    file.open( name );
    file << content;
    file.close();
}

std::string readFile( const std::string& name ) {
    std::ifstream t( name );
    std::string res = std::string( std::istreambuf_iterator<char>( t ), std::istreambuf_iterator<char>() );
    t.close();

    return res;
}

std::string writeBackFile( const std::string& serial, const std::string& cert, const std::string& keydir ) {
    std::string filename = keydir;
    mkdir( filename.c_str(), 0755 );
    filename += "/crt";
    mkdir( filename.c_str(), 0755 );
    std::string first;

    if( serial.length() < 3 ) {
        first = "0";
    } else {
        first = serial.substr( 0, serial.length() - 3 );
    }

    filename += "/" + first;
    mkdir( filename.c_str(), 0755 );
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

    std::tm t;
    t.tm_sec = 0;
    t.tm_min = 0;
    t.tm_hour = 0;
    t.tm_year = std::stoi( date.substr( 0, 4 ) ) - 1900;
    t.tm_mon = std::stoi( date.substr( 5, 2 ) ) - 1;
    t.tm_mday = std::stoi( date.substr( 8, 2 ) );
    setenv( "TZ", "UTC", 1 );
    tzset();
    std::time_t res = mktime( &t );
    char check[11];
    std::size_t siz = strftime( check, 11, "%Y-%m-%d", &t );

    if( siz != 10 ) {
        return std::pair<bool, time_t>( false, 0 );
    }

    std::string checkS( check, siz );

    if( checkS != date ) {
        return std::pair<bool, time_t>( false, 0 );
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
