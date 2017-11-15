#include "psql.h"

#include <stdio.h>

#include <iostream>

#include <log/logger.hpp>
#include <exception>

PostgresJobProvider::PostgresJobProvider( const std::string& server, const std::string& user, const std::string& password, const std::string& database ):
    c( "dbname=" + database + " host=" + server + " user=" + user + " password=" + password + " client_encoding=UTF-8 application_name=cassiopeia-client" ) {
    // TODO better connection string generation??
    pqxx::work txn( c );
    pqxx::result version = txn.exec( "SELECT \"version\" FROM \"schemeVersion\"" );

    if( version.size() != 1 ) {
        throw std::runtime_error( "Only one version row expected but multiple found." );
    }

    if( version[0][0].as<int>() < 33 ) {
        throw std::runtime_error( "Requires at least database schema version 33. Please update gigi before restarting cassiopeia." );
    }
}


std::shared_ptr<Job> PostgresJobProvider::fetchJob() {
    std::string q = "SELECT id, \"targetId\", task, \"executeFrom\", \"executeTo\", attempt FROM jobs WHERE state='open' AND attempt < 3";
    pqxx::work txn( c );
    pqxx::result result = txn.exec( q );


    auto job = std::make_shared<Job>();

    if( result.size() == 0 ) {
        return nullptr;
    }

    job->id = result[0]["id"].as<std::string>();
    job->target =  result[0]["\"targetId\""].as<std::string>();
    job->task = result[0]["task"].as<std::string>();
    job->from = result[0]["\"executeFrom\""].as<std::string>( "" );
    job->to = result[0]["\"executeTo\""].as<std::string>( "" );
    job->attempt = result[0]["attempt"].as<std::string>();

    logger::notef( "Got a job: (id=%s, target=%s, task=%s, from=%s, to=%s, attempts=%s)", job->id, job->target, job->task, job->from, job->to, job->attempt );
    return job;
}

void PostgresJobProvider::finishJob( std::shared_ptr<Job> job ) {
    pqxx::work txn( c );

    std::string q = "UPDATE jobs SET state='done' WHERE id=" + txn.quote( job->id );
    pqxx::result r = txn.exec( q );

    if( r.affected_rows() != 1 ) {
        throw std::runtime_error( "No database entry found." );
    }

    c.prepare( "insertLog", "INSERT INTO \"jobLog\"(\"jobid\", \"attempt\", \"content\") VALUES($1,$2,$3)" );
    txn.prepared( "insertLog" )( job->id )( job->attempt )( job->log.str() ).exec();

    txn.commit();
}

void PostgresJobProvider::failJob( std::shared_ptr<Job> job ) {
    pqxx::work txn( c );

    std::string q = "UPDATE jobs SET attempt = attempt + 1 WHERE id=" + txn.quote( job->id );
    pqxx::result r = txn.exec( q );

    if( r.affected_rows() != 1 ) {
        throw std::runtime_error( "No database entry found." );
    }

    c.prepare( "insertLog", "INSERT INTO \"jobLog\"(\"jobid\", \"attempt\", \"content\") VALUES($1,$2,$3)" );
    txn.prepared( "insertLog" )( job->id )( job->attempt )( job->log.str() ).exec();

    txn.commit();
}

std::shared_ptr<TBSCertificate> PostgresJobProvider::fetchTBSCert( std::shared_ptr<Job> job ) {
    pqxx::work txn( c );
    auto cert = std::make_shared<TBSCertificate>();
    std::string q = "SELECT md, profile, csr_type, keyname, att.content AS csr FROM certs INNER JOIN profiles ON profiles.id = certs.profile INNER JOIN \"certificateAttachment\" att ON att.certid=certs.id AND att.type='CSR' WHERE certs.id=" + txn.quote( job->target );
    pqxx::result r = txn.exec( q );

    if( r.size() != 1 ) {
        throw std::runtime_error( "Error, no or multiple certs found" );
    }

    auto ro = r[0];

    std::string profileName = ro["keyname"].as<std::string>();

    cert->md = ro["md"].as<std::string>();
    std::string profileId = ro["profile"].as<std::string>();

    while( profileId.size() < 4 ) {
        profileId = "0" + profileId;
    }

    cert->profile = profileId + "-" + profileName;

    cert->csr_content = ro["csr"].as<std::string>();
    cert->csr_type = ro["csr_type"].as<std::string>();

    cert->SANs = std::vector<std::shared_ptr<SAN>>();

    q = "SELECT contents, type FROM \"subjectAlternativeNames\" WHERE \"certId\"=" + txn.quote( job->target );
    r = txn.exec( q );

    std::cout << "Fetching SANs" << std::endl;

    for( auto row = r.begin(); row != r.end(); ++row ) {
        auto nSAN = std::make_shared<SAN>();
        nSAN->content = row["contents"].as<std::string>();
        nSAN->type = row["type"].as<std::string>();
        cert->SANs.push_back( nSAN );
    }

    q = "SELECT name, value FROM \"certAvas\" WHERE \"certId\"=" + txn.quote( job->target );
    r = txn.exec( q );

    for( auto row = r.begin(); row != r.end(); ++row ) {
        auto nAVA = std::make_shared<AVA>();
        nAVA->name = row["name"].as<std::string>();
        nAVA->value = row["value"].as<std::string>();
        cert->AVAs.push_back( nAVA );
    }

    return cert;
}

std::string pgTime( std::string isoTime ) {
    return isoTime.substr( 0, 8 ) + " " + isoTime.substr( 8, 6 );
}

void PostgresJobProvider::writeBack( std::shared_ptr<Job> job, std::shared_ptr<SignedCertificate> res ) {
    pqxx::work txn( c );
    std::string id = "SELECT id FROM cacerts WHERE keyname=" + txn.quote( res->ca_name );
    pqxx::result r = txn.exec( id );

    std::string read_id;

    if( r.size() != 1 ) {
        throw std::runtime_error( "Error while inserting new ca cert not found" );
    } else {
        read_id = r[0]["id"].as<std::string>();
    }

    std::string serial = res->serial;
    std::transform( serial.begin(), serial.end(), serial.begin(), ::tolower );

    if( serial[0] == '0' ) {
        serial = serial.substr( 1 );
    }

    std::string q = "UPDATE certs SET serial=" + txn.quote( serial ) + ", \"caid\" = " + txn.quote( read_id ) + ", created=" + txn.quote( pgTime( res->before ) ) + ", expire=" + txn.quote( pgTime( res->after ) ) + "  WHERE id=" + txn.quote( job->target );
    // TODO write more thingies back

    r = txn.exec( q );

    if( r.affected_rows() != 1 ) {
        throw std::runtime_error( "Only one row should be updated." );
    }

    c.prepare( "insertCrt", "INSERT INTO \"certificateAttachment\"(\"certid\", \"type\", \"content\") VALUES($1,'CRT',$2)" );
    txn.prepared( "insertCrt" )( job->target )( res->certificate ).exec();

    txn.commit();
}

std::pair<std::string, std::string> PostgresJobProvider::getRevocationInfo( std::shared_ptr<Job> job ) {
    pqxx::work txn( c );
    std::string q = "SELECT certs.serial, cacerts.keyname FROM certs INNER JOIN cacerts ON certs.\"caid\" = cacerts.id WHERE certs.id = " + txn.quote( job->target );

    pqxx::result r = txn.exec( q );

    if( r.size() != 1 ) {
        throw std::runtime_error( "Only one row expected but multiple found." );
    }

    return {r[0][0].as<std::string>(), r[0][1].as<std::string>()};
}

void PostgresJobProvider::writeBackRevocation( std::shared_ptr<Job> job, std::string date ) {
    logger::notef( "Revoking at %s", date );
    pqxx::work txn( c );
    logger::note( "executing" );
    pqxx::result r = txn.exec( "UPDATE certs SET revoked = " + txn.quote( pgTime( date ) ) + " WHERE id = " + txn.quote( job->target ) );

    if( r.affected_rows() != 1 ) {
        throw std::runtime_error( "Only one row should be updated." );
    }

    logger::note( "committing" );
    txn.commit();
    logger::note( "committed" );
}
