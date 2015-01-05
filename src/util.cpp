#include "util.h"

#include <sys/stat.h>

#include <fstream>

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
