#include "util.h"

#include <fstream>

void writeFile( const std::string& content, const std::string& name ) {
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
