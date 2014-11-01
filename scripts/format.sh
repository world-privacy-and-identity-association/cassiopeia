#!/bin/sh
astyle --style=java --add-brackets --indent-col1-comments --break-blocks --pad-oper --pad-paren-in --unpad-paren --indent-namespaces --align-pointer=type --align-reference=type --convert-tabs --lineend=linux -r "*.cpp" "*.h"
