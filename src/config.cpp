#include <iostream>
#include <vector>
#include <fstream>
#include <dirent.h>
#include <unordered_map>

#include "crypto/sslUtil.h"

#include "log/logger.hpp"

std::string keyDir;
std::unordered_map<std::string, Profile> profiles;
std::unordered_map<std::string, std::shared_ptr<CAConfig>> CAs;
std::string sqlHost, sqlUser, sqlPass, sqlDB;
std::string serialPath;
std::string crlPrefix;
std::string crtPrefix;

std::shared_ptr<std::unordered_map<std::string, std::string>> parseConf( std::string path ) {
    auto map = std::make_shared<std::unordered_map<std::string, std::string>>();
    std::ifstream config;
    config.open( path );

    if( !config.is_open() ) {
        logger::notef( "Where is \"%s\"?", path );
        throw std::runtime_error( "Config missing" );
    }

    std::string line1;

    while( std::getline( config, line1 ) ) {
        if( line1[0] == '#' || line1.size() == 0 ) {
            continue;
        }

        int splitter = line1.find( "=" );

        if( splitter == -1 ) {
            logger::warn( "Ignoring malformed config line: ", line1 );
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

    DIR *dp;
    struct dirent *ep;
    dp = opendir( "profiles" );

    if( dp == NULL ) {
        logger::error( "Profiles directory not found" );
        return -1;
    }

    while( ( ep = readdir( dp ) ) ) {
        if( ep->d_name[0] == '.' ) {
            continue;
        }

        std::string profileName( ep->d_name );

        int splitter = profileName.find( "-" );

        if( splitter == -1 ) {
            logger::warn( "Ignoring malformed profile: ", profileName );
            continue;
        }

        std::string id = profileName.substr( 0, splitter );

        if( profileName.substr( profileName.size() - 4 ) != ".cfg" ) {
            logger::warn( "Ignoring malformed profile: ", profileName );
            continue;
        }

        auto map = parseConf( std::string( "profiles/" ) + profileName );

        profileName = profileName.substr( 0, profileName.size() - 4 );

        Profile prof;
        prof.id = std::stoi( id );
        prof.eku = map->at( "eku" );
        prof.ku = map->at( "ku" );
        prof.maxValidity = std::stoi( map->at( "days" ) ) * /* DAYS */24 * 60 * 60;

        std::string cas = map->at( "ca" );

        DIR *dir;
        struct dirent *ent;

        if( ( dir = opendir( "ca" ) ) != NULL ) {
            while( ( ent = readdir( dir ) ) != NULL ) {
                std::string caName = std::string( ent->d_name );

                if( caName.find( cas ) != 0 ) {
                    continue;
                }

                if( CAs.find( caName ) == CAs.end() ) {
                    auto ca = std::make_shared<CAConfig>( caName );
                    CAs.emplace( caName, ca );
                }

                prof.ca.push_back( CAs.at( caName ) );
                logger::note( "Adding CA: ", caName );
            }

            closedir( dir );
        } else {
            throw std::runtime_error( "Directory with CAConfigs not found" );
        }

        profiles.emplace( profileName, prof );
        logger::notef( "Profile: \"%s\" up and running.", profileName );
    }

    ( void ) closedir( dp );

    logger::notef( "%s profiles loaded.", profiles.size() );

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
    crlPrefix = masterConf->at( "crlPrefix" );
    crtPrefix = masterConf->at( "crtPrefix" );

    if( keyDir == "" ) {
        logger::error( "Missing config property key.directory" );
        return -1;
    }

    if( parseProfiles() != 0 ) {
        return -1;
    }

    return 0;
}
