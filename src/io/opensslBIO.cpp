#include "opensslBIO.h"

OpensslBIOWrapper::OpensslBIOWrapper( std::shared_ptr<BIO> _b ) : b( _b ), buffer( 2*0xFFFF+20, 0 ), pos(0) {
}

OpensslBIOWrapper::~OpensslBIOWrapper() {
}

int OpensslBIOWrapper::write( const char* buf, int num ) {
    return BIO_write( b.get(), buf, num );
}

int OpensslBIOWrapper::read( char* buf, int size ) {
    return BIO_read( b.get(), buf, size );
}

long OpensslBIOWrapper::ctrl( int cmod, long arg1, void* arg2 ) {
    return BIO_ctrl( b.get(), cmod, arg1, arg2 );
}

int OpensslBIOWrapper::puts( const char* str ) {
    return BIO_puts( b.get(), str );
}

int OpensslBIOWrapper::gets( char* str, int size ) {
    return BIO_gets( b.get(), str, size );
}

const char* OpensslBIOWrapper::getName() {
    return "OpenSSLWrapper";
}
#include <log/logger.hpp>
std::string OpensslBIOWrapper::readLine(){
    int target = 0;
    while(1){
        logger::warn("doing data");
        while(target < pos){
            if(buffer[target] == '\n'){
                target++;
                std::string res(buffer.data(), 0, target);
                std::copy(buffer.data() + target, buffer.data() + pos, buffer.data() );
                pos -= target;
                logger::warn("emit");
                return res;
            }
            target++;
        }
        std::stringstream ss;
        ss << "target: " << target << ", pos:" << pos;
        logger::warn(ss.str());
        int dlen = read(buffer.data() + pos, buffer.size() - pos);
        if ( dlen <= 0 ){
            logger::warn(" error! ");
            throw EOFException();
        }
        std::stringstream ss2;
        ss2 << "done: " << dlen;
        logger::warn(ss2.str());
        pos += dlen;
    }
}
