#!/bin/sh
VERSION=$1
DIR_FILES=$2

sudo apt update
sudo apt-get install -y zip unzip

sudo sed -i "s/Version:.*/Version: ${VERSION}/" $DIR_FILES/Pack/src/DEBIAN/control
sudo sed -i "s/Source:.*/Source: r7mdaserver (${VERSION})/" $DIR_FILES/Pack/src/DEBIAN/control
sudo sed -i "s/Package:.*/Package: r7mdaserver/" $DIR_FILES/Pack/src/DEBIAN/control
sudo sed -i "s/Installed-Size:.*/Installed-Size: $(du -sk $DIR_FILES/Pack/src | cut -f1)/" $DIR_FILES/Pack/src/DEBIAN/control
( cd "$DIR_FILES/Pack/src" && rm -f DEBIAN/md5sums && find . -type f ! -path '*/DEBIAN/*' -exec md5sum {} > DEBIAN/md5sums \; )

sudo dpkg-deb -b $DIR_FILES/Pack/src $DIR_FILES/Packages/r7mdaserver-core_${VERSION}.deb