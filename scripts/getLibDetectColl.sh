#!/bin/bash

DETECTCOLL='lib/collissiondetect'
DETECTCOLL_URL='https://marc-stevens.nl/research/software/download.php?file=libdetectcoll-0.2.zip'

# Download source archive ...
wget -q -O "$DETECTCOLL/source.zip" "$DETECTCOLL_URL" || exit 1

#echo > "$DETECTCOLL/source.zip"

# Check SHA-512 and Whirlpool digests ...
echo "Verification (SHA-512) ..."
[ "d72153f1592628e31201cde17ce97f17fc83aeb65a6db075dfe1f21686d28e8068987215996c5c36f067819d16896fc75f7d990bf26cdb1472d61bf1b1d3c96c" = "$(sha512sum "$DETECTCOLL/source.zip"|cut '-d ' -f1)" ] || exit 2

echo "Verification (Whirlpool) ..."
[ "eaa3570095f3b60173241d9990c8da4b5bae5ef5f85880015918707275cb1cd556e6176d72c651085f05c8a2560d46431c5236acd116a7a862e128b0e35f3e37" = "$(openssl whirlpool -hex -r "$DETECTCOLL/source.zip"|cut '-d ' -f1)" ] || exit 2

# Unzip the code ...
echo "Unzipping $DETECTCOLL/source.zip ..."
pushd "$DETECTCOLL"
unzip -a "source.zip"
mv libdetectcoll-*/ "libdetectcoll"
popd

# Sorting extracted files ...
echo "Moving things around $DETECTCOLL/source.zip ..."
pushd "$DETECTCOLL/libdetectcoll"
mv "tests" "../tests"

mkdir -p "../lib"
mv libdetectcoll.c ../lib/
mv libdetectcoll.h ../lib/

mkdir -p "../src"
mv main.c ../src/

mv README ../
mv LICENSE ../

mv Makefile ../
popd

echo "Cleaning up ..."
rm -r "$DETECTCOLL/libdetectcoll"
