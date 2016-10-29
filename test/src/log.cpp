#include <iostream>
#include <sstream>
#include <stdexcept>

#include <boost/test/unit_test.hpp>

#include "log/logger.hpp"
#include "log/format.hpp"

BOOST_AUTO_TEST_SUITE( TestLogger )

static inline bool head_and_tail_equal( const std::string& str, const std::string& head, const std::string& tail ) {
    return str.size() >= head.size() + tail.size()
            and std::equal( head.begin(), head.end(), str.begin() )
            and std::equal( tail.rbegin(), tail.rend(), str.rbegin() )
            ;
}

BOOST_AUTO_TEST_CASE( basic_log ) {
    std::ostringstream stream{};
    auto logger = logger::logger_set{stream};

    logger.log( logger::level::note, "foo", " bar ", 23, ' ', 42.0, " baz" );

    BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: foo bar 23 42 baz\n" ) );
}

BOOST_AUTO_TEST_CASE( basic_logf ) {
    std::ostringstream stream{};
    auto logger = logger::logger_set{stream};

    logger.logf( logger::level::note, "bla%sblub%s%%", "foo", 42 );

    BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: blafooblub42%\n" ) );
}

BOOST_AUTO_TEST_CASE( log_hiding ) {
    std::ostringstream stream1{};
    auto logger1 = logger::logger_set{stream1};

    std::ostringstream stream2{};
    auto logger2 = logger::logger_set{stream2};

    logger::note( "foobar" );

    BOOST_CHECK( stream1.str().empty() );
    BOOST_CHECK( head_and_tail_equal( stream2.str(), "[note ][", "]: foobar\n" ) );
}

BOOST_AUTO_TEST_CASE( log_restoration ) {
    std::ostringstream stream1{};
    auto logger1 = logger::logger_set{stream1};

    {
        std::ostringstream stream2{};
        auto logger2 = logger::logger_set{stream2};
    }

    logger::note( "foobar" );

    BOOST_CHECK( head_and_tail_equal( stream1.str(), "[note ][", "]: foobar\n" ) );
}

BOOST_AUTO_TEST_CASE( non_global_log ) {
    std::ostringstream stream1{};
    auto logger1 = logger::logger_set{stream1};

    std::ostringstream stream2{};
    auto logger2 = logger::logger_set{{stream2}, logger::auto_register::off};

    logger::note( "foobar" );

    BOOST_CHECK( head_and_tail_equal( stream1.str(), "[note ][", "]: foobar\n" ) );
    BOOST_CHECK( stream2.str().empty() );
}

BOOST_AUTO_TEST_CASE( concat_alias_methods ) {
    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::debug}};

        logger.debug( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[debug][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::note}};

        logger.note( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::warn}};

        logger.warn( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[warn ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::error}};

        logger.error( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[error][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::fatal}};

        logger.fatal( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[fatal][", "]: foo\n" ) );
    }
}

BOOST_AUTO_TEST_CASE( format_alias_methods ) {
    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::debug}};

        logger.debugf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[debug][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::note}};

        logger.notef( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::warn}};

        logger.warnf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[warn ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::error}};

        logger.errorf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[error][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::fatal}};

        logger.fatalf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[fatal][", "]: foo\n" ) );
    }
}

BOOST_AUTO_TEST_CASE( concat_alias_functions ) {
    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::debug}};

        logger::debug( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[debug][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::note}};

        logger::note( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::warn}};

        logger::warn( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[warn ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::error}};

        logger::error( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[error][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::fatal}};

        logger::fatal( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[fatal][", "]: foo\n" ) );
    }
}

BOOST_AUTO_TEST_CASE( format_alias_functions ) {
    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::debug}};

        logger::debugf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[debug][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::note}};

        logger::notef( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[note ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::warn}};

        logger::warnf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[warn ][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::error}};

        logger::errorf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[error][", "]: foo\n" ) );
    }

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{{stream, logger::level::fatal}};

        logger::fatalf( "foo" );

        BOOST_CHECK( head_and_tail_equal( stream.str(), "[fatal][", "]: foo\n" ) );
    }
}

BOOST_AUTO_TEST_CASE( formatting_exceptions ) {
    std::ostringstream stream{};
    auto logger = logger::logger_set{stream};

    BOOST_CHECK_THROW( logger.notef( "%" ), std::invalid_argument );
    BOOST_CHECK_THROW( logger.notef( "%s" ), std::invalid_argument );
    BOOST_CHECK_THROW( logger.notef( "%e" ), std::invalid_argument );
}

BOOST_AUTO_TEST_CASE( multiple_calls ) {
    std::ostringstream stream{};
    auto logger = logger::logger_set{stream};

    logger::note( "foo1" );
    logger::debug( "foo2" );
    logger::warn( "foo3" );
    logger::note( "foo4" );

    const auto result = stream.str();

    const auto foo1 = result.find( "foo1" );
    const auto foo2 = result.find( "foo2" );
    const auto foo3 = result.find( "foo3" );
    const auto foo4 = result.find( "foo4" );

    BOOST_CHECK_LT( foo1, foo3 );
    BOOST_CHECK_LT( foo3, foo4 );
    BOOST_CHECK_NE( foo4, std::string::npos );
    BOOST_CHECK_EQUAL( foo2, std::string::npos );
}

BOOST_AUTO_TEST_CASE( multiple_calls_nested ) {
    std::ostringstream stream{};
    auto logger = logger::logger_set{stream};

    logger::note( "foo1" );

    {
        std::ostringstream stream{};
        auto logger = logger::logger_set{stream};

        logger::note( "foo2" );
    }

    logger::note( "foo3" );

    const auto result = stream.str();
    const auto foo1 = result.find( "foo1" );
    const auto foo2 = result.find( "foo2" );
    const auto foo3 = result.find( "foo3" );

    BOOST_CHECK_LT( foo1, foo3 );
    BOOST_CHECK_NE( foo3, std::string::npos );
    BOOST_CHECK_EQUAL( foo2, std::string::npos );
}

BOOST_AUTO_TEST_CASE( extending_current_logger ) {
    std::ostringstream stream1{};
    auto logger1 = logger::logger_set{stream1};

    std::ostringstream stream2{};
    {
        auto logger2 = logger::current_logger_extended( {stream2} );
        logger::note( "foo1" );
    }

    BOOST_CHECK( head_and_tail_equal( stream1.str(), "[note ][", "]: foo1\n" ) );
    BOOST_CHECK( head_and_tail_equal( stream2.str(), "[note ][", "]: foo1\n" ) );

    stream1.str( "" );
    stream2.str( "" );

    logger::note( "foo2" );

    BOOST_CHECK( head_and_tail_equal( stream1.str(), "[note ][", "]: foo2\n" ) );
    BOOST_CHECK( stream2.str().empty() );
}

BOOST_AUTO_TEST_CASE( closed_filestream_exception ) {
    std::ofstream stream;

    BOOST_CHECK_THROW( logger::logger_set {stream}, std::runtime_error );
}

BOOST_AUTO_TEST_CASE( formated_strings ) {
    using namespace logger::format::literals;
    using logger::conv::to_string;

    BOOST_CHECK_EQUAL( to_string( ""_fmt( "foo" ) ), "foo" );
    BOOST_CHECK_EQUAL( to_string( "_3"_fmt( "foo" ) ), "foo" );
    BOOST_CHECK_EQUAL( to_string( "_6"_fmt( "foo" ) ), "foo___" );
    BOOST_CHECK_EQUAL( to_string( "_10l"_fmt( "foo" ) ), "foo_______" );
    BOOST_CHECK_EQUAL( to_string( "_10r"_fmt( "foo" ) ), "_______foo" );
}

BOOST_AUTO_TEST_CASE( formated_ints ) {
    using namespace logger::format::literals;
    using logger::conv::to_string;

    BOOST_CHECK_EQUAL( to_string( ""_fmt( 3 ) ), "3" );
    BOOST_CHECK_EQUAL( to_string( "03"_fmt( 3 ) ), "003" );
    BOOST_CHECK_EQUAL( to_string( "03"_fmt( 13 ) ), "013" );
    BOOST_CHECK_EQUAL( to_string( "03x"_fmt( 13 ) ), "00d" );
    BOOST_CHECK_EQUAL( to_string( "03o"_fmt( 13 ) ), "015" );
    BOOST_CHECK_EQUAL( to_string( "03d"_fmt( 13 ) ), "013" );
    BOOST_CHECK_EQUAL( to_string( "03s"_fmt( 13 ) ), "013" );
}

BOOST_AUTO_TEST_CASE( formated_ints_variadic_api ) {
    using logger::conv::to_string;
    using logger::format::fmt;

    BOOST_CHECK_EQUAL( to_string( fmt( 3 ) ), "3" );
    BOOST_CHECK_EQUAL( to_string( fmt( 3, logger::format::width_t {3} ) ), "  3" );
}

BOOST_AUTO_TEST_CASE( formated_ints_variadic_api_literals ) {
    using logger::conv::to_string;
    using logger::format::fmt;

    using namespace logger::format::literals;

    BOOST_CHECK_EQUAL( to_string( fmt( 3 ) ), "3" );
    BOOST_CHECK_EQUAL( to_string( fmt( 3, 3_w ) ), "  3" );
    BOOST_CHECK_EQUAL( to_string( fmt( 10, 3_w, 8_b, 'x'_f ) ), "x12" );
}

BOOST_AUTO_TEST_SUITE_END()
