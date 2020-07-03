#!/bin/bash

if [ ! -e setup.sh ] ; then
    echo "ERROR: you must echo SNORT=/path/to/snort/dir > setup.sh first"
    exit -1
fi

. ./setup.sh

export SNORT_PP_DEBUG=0x80000000
$SNORT/src/snort -c test/snort.conf -A console:test -r test/test.pcap
