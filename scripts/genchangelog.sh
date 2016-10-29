cd "$(dirname $0)"
cat > ../debian/changelog <<EOF
cacert-cassiopeia (0.1.b${BUILD_NUMBER}-$(git rev-parse HEAD)) unstable; urgency=low

  * Initial Release.

 -- CAcert Software Team <cacert-devel@cacert.org>  $(LANG=C date "+%a, %d %b %Y %H:%M:%S %z")
EOF
