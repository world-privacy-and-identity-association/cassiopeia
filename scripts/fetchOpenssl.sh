!/bin/sh
mkdir -p ../lib/openssl
cd ../lib/openssl

wget -O openssl.tar.gz https://www.openssl.org/source/openssl-1.0.1j.tar.gz
echo "Verifying sha1"
[ "cff86857507624f0ad42d922bb6f77c4f1c2b819" = "$(sha1sum "openssl.tar.gz"|cut '-d ' -f1)" ] || exit 2

echo "Verifying sha512"
[ "a786bb99b68d88c1de79d3c5372767f091ebeefb5abc1d4883253fd3ab5a86af53389f5ff36fdd8faa27c5fb78be8bbff406392c373358697da80d250eadebb8" = "$(sha512sum "openssl.tar.gz"|cut '-d ' -f1)" ] || exit 2

tar xf openssl.tar.gz
mv openssl-*/* .
rmdir openssl-*

rm openssl.tar.gz
