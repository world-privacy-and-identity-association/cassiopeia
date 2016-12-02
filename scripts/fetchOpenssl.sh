#!/bin/sh
mkdir -p ../lib/openssl
cd ../lib/openssl

wget -O openssl.tar.gz https://www.openssl.org/source/openssl-1.1.0c.tar.gz
echo "Verifying sha1"
[ "920e6e7bdaccd94d7564af1097176f11900d20ca" = "$(sha1sum "openssl.tar.gz"|cut '-d ' -f1)" ] || exit 2

echo "Verifying sha512"
[ "e3cfba6c682e5edd6f678df7c1da9c9713880f7dca248e6d62f095185c22ce8fd7571d53a54a119fb5d4422578637746ad2809bb2ba324a5c54564f532307ad9" = "$(sha512sum "openssl.tar.gz"|cut '-d ' -f1)" ] || exit 2

tar xf openssl.tar.gz
mv openssl-*/* .
mv openssl-*/.* .
rmdir openssl-*

rm openssl.tar.gz
