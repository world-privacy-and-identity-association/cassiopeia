#!/bin/sh
exec astyle --style=java --add-brackets --indent-col1-comments --break-blocks --pad-oper --pad-paren-in --unpad-paren --indent-namespaces --align-pointer=name --align-reference=type --convert-tabs --lineend=linux --suffix=none --exclude=lib --recursive "*.cpp" "*.h" '*.hpp'
