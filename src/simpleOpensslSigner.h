#pragma once

#include "database.h"
#include "signer.h"

class SimpleOpensslSigner : public Signer {
public:
    void sign( std::shared_ptr<TBSCertificate> cert );
};
