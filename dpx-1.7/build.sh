#!/bin/bash

if [ ! -e setup.sh ] ; then
    echo "ERROR: you must echo SNORT=/path/to/snort/dir > setup.sh first"
    exit -1
fi

. setup.sh

if [ ! -e $SNORT/snort.pc.in ] ; then
    echo "ERROR: cannot find Snort source files. Is this the correct path?"
    echo "       SNORT=$SNORT"
    exit -1
fi

if [ ! -e $SNORT/snort.pc ] ; then
    echo "ERROR: Snort must be configured and built first"
    exit -1
fi

export PKG_CONFIG_PATH=$SNORT

autoreconf -isvf
#libtoolize --automake --copy
#aclocal -I m4
#autoheader
#automake --add-missing --copy
#autoconf

./configure --with-dpx-includes=$SNORT/src/dynamic-examples/include --prefix=`pwd`

# i'm gonna burn in autohell for this ...
echo "#define HAVE_WCHAR_H 1" >> config.h

make clean
make
make install
