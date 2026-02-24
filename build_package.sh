#!/bin/sh
VERSION=$1
DIR_FILES=$2

sudo apt update
sudo apt-get install -y zip unzip

sudo sed -i "s/Version:.*/Version: ${VERSION}/" $DIR_FILES/Pack/src/DEBIAN/control
sudo sed -i "s/Source:.*/Source: r7mdaserver (${VERSION})/" $DIR_FILES/Pack/src/DEBIAN/control
sudo sed -i "s/Package:.*/Package: r7mdaserver/" $DIR_FILES/Pack/src/DEBIAN/control
size_inKb=$(du -sk $DIR_FILES/Pack/src | cut -f1)
sudo sed -i "s/Installed-Size:.*/Installed-Size: ${size_inKb}/" $DIR_FILES/Pack/src/DEBIAN/control

NOWDIR=$PWD
cd $DIR_FILES/Pack/src
find . -type f ! -path '*/DEBIAN/*' -exec md5sum {} > DEBIAN/md5sums \;
cd $NOWDIR
sudo dpkg-deb -b $DIR_FILES/Pack/src $DIR_FILES/Packages/r7mdaserver-core_${VERSION}.deb
rm -f $DIR_FILES/Pack/src/DEBIAN/md5sums

#cd $DIR_FILES/Pack/src/ && sudo zip -r $DIR_FILES/Packages/r7mdaserver_${VERSION}.zip *
#sudo md5sum $DIR_FILES/Packages/r7mdaserver_${VERSION}.zip >> $DIR_FILES/Packages/md5.txt
#Deprecated in build-server
#cd $DIR_FILES && sudo zip -r $DIR_FILES/Packages/src_dovecot_${VERSION}.zip * -x $DIR_FILES/Packages/src_dovecot_${VERSION}.zip