#pragma once

#include <string>
#include <memory>

#include "crypto/sslUtil.h"

class CRL {
private:
    std::shared_ptr<X509_CRL> crl;
public:
    CRL( std::string path );

    /**
     * Adds the serial to this serial.
     * @param serial the serial to remove (as hex string)
     * @param time the "revokation time" (der-encoded)
     * @returns DER-encoded TIME of the revoked time
     */
    std::string revoke( std::string serial, std::string time );

    /**
     * Signs this CRL.
     * @param ca the CA to sign with
     */
    void sign( std::shared_ptr<CAConfig> ca );

    bool verify( std::shared_ptr<CAConfig> ca );

    std::string getSignature();
    void setSignature( std::string signature );

    std::string toString();
};
