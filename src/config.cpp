#include <iostream>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <unordered_map>

#include "crypto/sslUtil.h"

std::string keyDir;
std::unordered_map<std::string, Profile> profiles;
std::unordered_map<std::string, std::shared_ptr<CAConfig>> CAs;
std::string sqlHost, sqlUser, sqlPass, sqlDB;
std::string serialPath;

std::shared_ptr<std::unordered_map<std::string, std::string>> parseConf( std::string path ) {
    std::shared_ptr<std::unordered_map<std::string, std::string>> map( new std::unordered_map<std::string, std::string>() );
    std::ifstream config;
    config.open( path );

    if( !config.is_open() ) {
        std::cout << "Where is " << path << "?" << std::endl;
        throw "Config missing";
    }

    std::string line1;

    while( std::getline( config, line1 ) ) {
        if( line1[0] == '#' || line1.size() == 0 ) {
            continue;
        }

        int splitter = line1.find( "=" );

        if( splitter == -1 ) {
            std::cerr << "Ignoring malformed config line: " << line1 << std::endl;
            continue;
        }

        std::string key = line1.substr( 0, splitter );
        std::string value = line1.substr( splitter + 1 );
        map->emplace( key, value );
    }

    config.close();

    return map;
}

int parseProfiles() {
    CAs = std::unordered_map<std::string, std::shared_ptr<CAConfig>>();

    DIR* dp;
    struct dirent* ep;
    dp = opendir( "profiles" );

    if( dp == NULL ) {
        std::cerr << "Profiles not found " << std::endl;
        return -1;
    }

    while( ( ep = readdir( dp ) ) ) {
        if( ep->d_name[0] == '.' ) {
            continue;
        }

        std::string profileName( ep->d_name );

        int splitter = profileName.find( "-" );

        if( splitter == -1 ) {
            std::cerr << "Ignoring malformed profile: " << profileName << std::endl;
            continue;
        }

        std::string id = profileName.substr( 0, splitter );

        if( profileName.substr( profileName.size() - 4 ) != ".cfg" ) {
            std::cerr << "Ignoring malformed profile: " << profileName << std::endl;
            continue;
        }

        auto map = parseConf( std::string( "profiles/" ) + profileName );

        profileName = profileName.substr( 0, profileName.size() - 4 );

        Profile prof;
        prof.id = std::stoi( id );
        prof.eku = map->at( "eku" );
        prof.ku = map->at( "ku" );

        std::string cas = map->at( "ca" );

        for( size_t pos = 0; pos != std::string::npos; ) {
            size_t end = cas.find( ",", pos );
            std::string sub;

            if( end == std::string::npos ) {
                sub = cas.substr( pos );
            } else {
                sub = cas.substr( pos, end - pos );
                end++;
            }

            pos = end;

            if( CAs.find( sub ) == CAs.end() ) {
                std::shared_ptr<CAConfig> ca( new CAConfig( sub ) );
                CAs.emplace( sub, ca );
            }

            prof.ca.push_back( CAs.at( sub ) );

        }

        profiles.emplace( profileName, prof );
        std::cout << "Profile: " << profileName << " up and running." << std::endl;
    }

    ( void ) closedir( dp );


    std::cout << profiles.size() << " profiles loaded." << std::endl;

    return 0;
}

int parseConfig( std::string path ) {

    auto masterConf = parseConf( path );

    keyDir = masterConf->at( "key.directory" );
    sqlHost = masterConf->at( "sql.host" );
    sqlUser = masterConf->at( "sql.user" );
    sqlPass = masterConf->at( "sql.password" );
    sqlDB = masterConf->at( "sql.database" );
    serialPath = masterConf->at( "serialPath" );

    if( keyDir == "" ) {
        std::cerr << "Missing config property key.directory" << std::endl;
        return -1;
    }

    if( parseProfiles() != 0 ) {
        return -1;
    }

    return 0;
}
