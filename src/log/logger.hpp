#pragma once

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <stdexcept>

namespace logger {

    /**
     * conv::to_string will be used to convert whatever argument is send
     * to the logger to a string. If another type shall be supported,
     * just add the appropriate overload and you can start using it right
     * away. The default conversion will use a stringstream.
     */
    namespace conv {
        template <typename T>
        inline std::string to_string( const T& arg ) {
            std::ostringstream stream;
            stream << arg;
            return stream.str();
        }
        inline std::string to_string( std::string&& arg ) {
            return arg;
        }
        inline std::string to_string( const std::string& arg ) {
            return arg;
        }
        inline std::string to_string( const char* arg ) {
            return arg;
        }

    } // namespace conv

    enum class level {
        debug, note, warn, error, fatal
    };

    const auto default_level = level::note;

    struct log_target {
        log_target( std::ostream& stream, level min_level = default_level ):
            stream {&stream}, min_level {min_level} {}
        log_target( std::ofstream& stream, level min_level = default_level ):
            stream {&stream}, min_level {min_level} {
            if( !stream.is_open() ) {
                throw std::runtime_error {"logfile not open"};
            }
        }
        std::ostream* stream;
        level min_level;
    };

    class logger_set;
    namespace impl {
        void reassign_stack_pointer( logger_set*& ptr );
    }

    /**
     * Provides controll over wether a logger should automatically register itself
     */
    enum class auto_register {
        on, off
    };

    class logger_set {
    public:
        logger_set( std::initializer_list<log_target> lst, auto_register = auto_register::on );

        logger_set( logger_set&& ) noexcept;
        logger_set& operator=( logger_set && ) noexcept;
        ~logger_set();

        template<typename... Args>
        void log( level l, Args&& ... args );
        template<typename... Args>
        void logf( level l, const std::string& format, Args&& ... args );

        template<typename... Args>
        void debug( Args&& ... args );
        template<typename... Args>
        void debugf( const std::string& format, Args&& ... args );

        template<typename... Args>
        void note( Args&& ... args );
        template<typename... Args>
        void notef( const std::string& format, Args&& ... args );

        template<typename... Args>
        void warn( Args&& ... args );
        template<typename... Args>
        void warnf( const std::string& format, Args&& ... args );

        template<typename... Args>
        void error( Args&& ... args );
        template<typename... Args>
        void errorf( const std::string& format, Args&& ... args );

        template<typename... Args>
        void fatal( Args&& ... args );
        template<typename... Args>
        void fatalf( const std::string& format, Args&& ... args );

        friend void impl::reassign_stack_pointer( logger_set*& ptr );
        friend logger_set current_logger_extended( std::initializer_list<log_target> further_targets );
    private:
        void log_impl( level l, const std::string& msg );

        std::vector<log_target> m_loggers;
        logger_set** m_stackpointer = nullptr;
        level m_min_level;
    };

    logger_set current_logger_extended( std::initializer_list<log_target> further_targets );

    namespace impl {
        std::string concat_msg( level l, const std::vector<std::string>& args );
        std::string format_msg( level l, const std::string&, std::vector<std::string> args );
        logger_set& active_logger();
    }

    template <typename... Args>
    void logger_set::log( level l, Args&& ... data ) {
        if( l < m_min_level ) {
            return;
        }

        log_impl( l, impl::concat_msg( l, {conv::to_string( std::forward<Args>( data ) )...} ) );
    }

    template <typename... Args>
    void logger_set::logf( level l, const std::string& format, Args&& ... data ) {
        if( l < m_min_level ) {
            return;
        }

        log_impl( l, impl::format_msg( l, format, {conv::to_string( std::forward<Args>( data ) )...} ) );
    }

    template <typename... Args>
    void log( level l, Args&& ... args ) {
        impl::active_logger().log( l, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logf( level l, const std::string& format, Args&& ... args ) {
        impl::active_logger().logf( l, format, std::forward<Args>( args )... );
    }

    // concat-based methods
    template <typename... Args>
    void logger_set::debug( Args&& ... args ) {
        log( level::debug, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::note( Args&& ... args ) {
        log( level::note, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::warn( Args&& ... args ) {
        log( level::warn, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::error( Args&& ... args ) {
        log( level::error, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::fatal( Args&& ... args ) {
        log( level::fatal, std::forward<Args>( args )... );
    }

    // format-based methods
    template <typename... Args>
    void logger_set::debugf( const std::string& fmt, Args&& ... args ) {
        logf( level::debug, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::notef( const std::string& fmt, Args&& ... args ) {
        logf( level::note, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::warnf( const std::string& fmt, Args&& ... args ) {
        logf( level::warn, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::errorf( const std::string& fmt, Args&& ... args ) {
        logf( level::error, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void logger_set::fatalf( const std::string& fmt, Args&& ... args ) {
        logf( level::fatal, fmt, std::forward<Args>( args )... );
    }

    // global concat-based
    template <typename... Args>
    void debug( Args&& ... args ) {
        log( level::debug, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void note( Args&& ... args ) {
        log( level::note, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void warn( Args&& ... args ) {
        log( level::warn, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void error( Args&& ... args ) {
        log( level::error, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void fatal( Args&& ... args ) {
        log( level::fatal, std::forward<Args>( args )... );
    }

    // global format-based
    template <typename... Args>
    void debugf( const std::string& fmt, Args&& ... args ) {
        logf( level::debug, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void notef( const std::string& fmt, Args&& ... args ) {
        logf( level::note, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void warnf( const std::string& fmt, Args&& ... args ) {
        logf( level::warn, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void errorf( const std::string& fmt, Args&& ... args ) {
        logf( level::error, fmt, std::forward<Args>( args )... );
    }
    template <typename... Args>
    void fatalf( const std::string& fmt, Args&& ... args ) {
        logf( level::fatal, fmt, std::forward<Args>( args )... );
    }

}
