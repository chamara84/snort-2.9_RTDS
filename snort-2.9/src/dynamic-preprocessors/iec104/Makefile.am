# $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs $GLIB_CFLAGS

dynamicpreprocessordir = ${libdir}/snort_dynamicpreprocessor

dynamicpreprocessor_LTLIBRARIES = libsf_iec104_preproc.la

libsf_iec104_preproc_la_LDFLAGS = -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_iec104_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
libsf_iec104_preproc_la_LIBADD += -lglib-2.0
if BUILD_SNORT_RELOAD
libsf_iec104_preproc_la_LIBADD += ../libsf_dynamic_utils.la
libsf_iec104_preproc_la_LIBADD += -lglib-2.0
endif
else
nodist_libsf_iec104_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c \
../include/mempool.c \
../include/sf_sdlist.c
nodist_libsf_iec104_preproc_la_LIBADD = -lglib-2.0
if BUILD_SNORT_RELOAD
nodist_libsf_iec104_preproc_la_SOURCES += ../include/appdata_adjuster.c ../include/sfxhash.c ../include/sfhashfcn.c ../include/sfmemcap.c ../include/sfprimetable.c ../include/reg_test.h ../include/reg_test.c
endif
endif

libsf_iec104_preproc_la_SOURCES = \
spp_iec104.c \
spp_iec104.h \
iec104_paf.c \
iec104_paf.h \
iec104_reassembly.c \
iec104_reassembly.h 

if BUILD_BUFFER_DUMP
libsf_iec104_preproc_la_SOURCES += \
iec104_buffer_dump.c \
iec104_buffer_dump.h
endif


EXTRA_DIST = \
sf_iec104.dsp

all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-dynamicpreprocessorLTLIBRARIES

