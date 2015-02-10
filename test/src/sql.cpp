#include <boost/test/unit_test.hpp>
#include <memory.h>
#include <db/mysql.h>
#include <config.h>

extern std::string sqlHost, sqlUser, sqlPass, sqlDB;

BOOST_AUTO_TEST_SUITE( TestTime )

BOOST_AUTO_TEST_CASE( testSQL ) {
    BOOST_REQUIRE( parseConfig("config.txt") == 0 );
    std::shared_ptr<MySQLJobProvider> jp( new MySQLJobProvider( sqlHost, sqlUser, sqlPass, sqlDB ) );
    BOOST_REQUIRE( jp->query( "TRUNCATE TABLE profiles" ).first == 0 );
    BOOST_REQUIRE( jp->query( "TRUNCATE TABLE certs" ).first == 0 );
    BOOST_REQUIRE( jp->query( "TRUNCATE TABLE certAvas" ).first == 0 );
    BOOST_REQUIRE( jp->query( "TRUNCATE TABLE subjectAlternativeNames" ).first == 0 );
    BOOST_REQUIRE( jp->query( "TRUNCATE TABLE jobs" ).first == 0 );
    BOOST_REQUIRE( jp->query( "INSERT INTO profiles SET id='1', keyname='assured', keyUsage='', extendedKeyUsage='', name='assured'" ).first == 0 );
    BOOST_REQUIRE( jp->query( "INSERT INTO jobs SET task='sign', targetId='1'" ).first == 0 );

    std::shared_ptr<Job> job = jp->fetchJob();
    BOOST_REQUIRE( job );
    jp->failJob(job);
    BOOST_REQUIRE_EQUAL( job->target, "1" );
    BOOST_REQUIRE_EQUAL( job->task, "sign" );
    job = jp->fetchJob();
    BOOST_REQUIRE( job );
    std::shared_ptr<TBSCertificate> cert = jp->fetchTBSCert(job);
    BOOST_REQUIRE( !cert );
    BOOST_REQUIRE( jp->query( "INSERT INTO certs SET csr_type='CSR', id='1', profile='1'" ).first == 0 );
    BOOST_REQUIRE( jp->query( "INSERT INTO subjectAlternativeNames SET certId='1', contents='example.org', type='DNS'" ).first == 0 );
    BOOST_REQUIRE( jp->query( "INSERT INTO certAvas SET certid='1', name='CN', value='example.org'" ).first == 0 );
    cert = jp->fetchTBSCert(job);
    BOOST_REQUIRE( cert );

    std::shared_ptr<SignedCertificate> fcert( new SignedCertificate() );
    fcert->certificate="CERT";
    fcert->serial="1234";
    fcert->crt_name="crt.name.crt";
    fcert->ca_name="assured";
    jp->writeBack( job, fcert );
    jp->finishJob( job );
    BOOST_REQUIRE( !jp->fetchJob() );
    BOOST_REQUIRE( jp->query( "INSERT INTO jobs SET task='revoke', targetId='1'" ).first == 0 );
    job = jp->fetchJob();
    BOOST_REQUIRE_EQUAL( job->target, "1" );
    BOOST_REQUIRE_EQUAL( job->task, "revoke" );
    std::pair<std::string, std::string> revocationInfo = jp->getRevocationInfo( job );
    BOOST_REQUIRE_EQUAL( revocationInfo.first, "1234");
    BOOST_REQUIRE_EQUAL( revocationInfo.second, "assured");
    jp->writeBackRevocation( job, "2000-01-01 01:01:01" );
    jp->finishJob( job );
}

BOOST_AUTO_TEST_CASE( testSQLDisconnected ) {
    //if(1) return;
    //BOOST_REQUIRE( parseConfig("config.txt") == 0 );
    std::shared_ptr<MySQLJobProvider> jp( new MySQLJobProvider( sqlHost, sqlUser, sqlPass, sqlDB ) );
    jp->disconnect();
    jp->disconnect();
    BOOST_REQUIRE( jp->query("SELECT 1").first);
    BOOST_REQUIRE_THROW( jp->escape_string("uia"), const char * );
    BOOST_REQUIRE_THROW( jp->finishJob(std::shared_ptr<Job>()), const char * );
    BOOST_REQUIRE_THROW( jp->failJob(std::shared_ptr<Job>()), const char * );
}

BOOST_AUTO_TEST_SUITE_END()
