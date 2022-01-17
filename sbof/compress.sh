#!/bin/bash

DIR_NAME="root"

if [ ! -z $1 ]
then
    DIR_NAME=$1
fi

# removing if it exists already
rm initramfs.cpio.gz

# build module
make clean_exploit
make
cp exploit root/exploit

# copy in module
cp sbof.ko root/

pushd $DIR_NAME
find . -print0 | cpio --null -ov --format=newc > initramfs.cpio
popd

gzip $DIR_NAME/initramfs.cpio
mv $DIR_NAME/initramfs.cpio.gz .
