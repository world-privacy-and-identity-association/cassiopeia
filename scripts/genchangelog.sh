cd "$(dirname $0)"
cat > ../debian/changelog <<EOF
wpia-cassiopeia ($(git describe HEAD --tags --match "v*" | sed "s/^v//")) unstable; urgency=low

  * Initial Release.

 -- WPIA Software Team <software@wpia.club>  $(LANG=C date "+%a, %d %b %Y %H:%M:%S %z")
EOF
