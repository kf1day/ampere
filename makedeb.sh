#!/bin/sh

CUR="`dirname $0`"
DEB="$CUR/deb"
VER="`sed -ne '/APP_VERSION/{s!.*APP_VERSION !!;s!\"!!g;p;q}' \"$CUR/src/main.c\"`"
ARCH="`uname -r | sed 's!.*-!!'`"

echo "Enter package version:"
read v

file="$CUR/ampere_$VER-${v}_$ARCH.deb"

echo "Creating package $file"

cp "$CUR/ampere" "$DEB/usr/sbin/"

printf \
"Package: ampere
Version: %s-%s
Architecture: %s
Section: net
Maintainer: Andrew Day <andrew.lugovoy@gmail.com>
Description: An active network filter for Asterisk PBX
" $VER $v $ARCH > "$DEB/DEBIAN/control"
find "$DEB" -type f -exec md5sum {} \; | sed '/DEBIAN/d;s!'$DEB'!!' > "$DEB/DEBIAN/md5sums"
fakeroot dpkg-deb --build "$DEB" "$file"
