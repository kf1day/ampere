#!/bin/sh

CUR="`dirname $0`"
DEB="$CUR/deb"
VER="`sed -ne '/APP_VERSION/{s!.*APP_VERSION !!;s!\"!!g;p;q}' \"$CUR/src/main.c\"`"
ARCH="`uname -r | sed 's!.*-!!'`"

echo "Enter package version:"
read v

file="$CUR/ampere_$VER-${v}_$ARCH.deb"

echo "Creating package $file"

mkdir -p "$DEB/DEBIAN"
tar -xzf "$CUR/deb-skel.tar.gz" -C "$DEB"
cp "$CUR/ampere" "$DEB/usr/sbin/"



printf "Package: ampere\nVersion: %s-%s\nArchitecture: %s\nSection: net\nMaintainer: Andrew Day <andrew.lugovoy@gmail.com>\nDescription: An active network filter for Asterisk PBX\n" $VER $v $ARCH > "$DEB/DEBIAN/control"
printf "/etc/ampere/ampere.cfg\n" > "$DEB/DEBIAN/conffiles"
printf "/var/lib/ampere\n/var/log\n" > "$DEB/DEBIAN/dirs"
cat "$CUR/LICENSE" > "$DEB/DEBIAN/copyright"
find "$DEB" -type f -exec md5sum {} \; | sed '/DEBIAN/d;s!'$DEB'!!' > "$DEB/DEBIAN/md5sums"

fakeroot dpkg-deb --build "$DEB" "$file"
