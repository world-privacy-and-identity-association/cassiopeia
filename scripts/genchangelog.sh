cd "$(dirname $0)"
cat > ../debian/changelog <<EOF
wpia-cassiopeia (0.1.b${BUILD_NUMBER}-$(git rev-parse HEAD)) unstable; urgency=low

  * Initial Release.

 -- WPIA Software Team <software@wpia.club>  $(LANG=C date "+%a, %d %b %Y %H:%M:%S %z")
EOF
