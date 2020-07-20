# $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs $GLIB_CFLAGS
dynamicpreprocessordir = ${libdir}/snort_dynamicpreprocessor

dynamicpreprocessor_LTLIBRARIES = libsf_iec61850_preproc.la

libsf_iec61850_preproc_la_LDFLAGS = -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_iec61850_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
libsf_iec61850_preproc_la_LIBADD += -lglib-2.0
if BUILD_SNORT_RELOAD
libsf_iec61850_preproc_la_LIBADD += ../libsf_dynamic_utils.la
libsf_iec61850_preproc_la_LIBADD += -lglib-2.0
endif
else
nodist_libsf_iec61850_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c \
../include/mempool.c \
../include/sf_sdlist.c
nodist_libsf_iec61850_preproc_la_LIBADD = -lglib-2.0
if BUILD_SNORT_RELOAD
nodist_libsf_iec61850_preproc_la_SOURCES += ../include/appdata_adjuster.c ../include/sfxhash.c ../include/sfhashfcn.c ../include/sfmemcap.c ../include/sfprimetable.c ../include/reg_test.h ../include/reg_test.c
endif
endif

libsf_iec61850_preproc_la_SOURCES = \
spp_iec61850.c \
spp_iec61850.h \
iec61850_paf.c \
iec61850_paf.h \
iec61850_reassembly.c \
iec61850_reassembly.h 

if BUILD_BUFFER_DUMP
libsf_iec61850_preproc_la_SOURCES += \
iec61850_buffer_dump.c \
iec61850_buffer_dump.h
endif


EXTRA_DIST = \
sf_iec61850.dsp

all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-dynamicpreprocessorLTLIBRARIES

