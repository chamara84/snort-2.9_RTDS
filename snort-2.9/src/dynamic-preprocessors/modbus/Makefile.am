## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs

dynamicpreprocessordir = ${libdir}/snort_dynamicpreprocessor

dynamicpreprocessor_LTLIBRARIES = libsf_modbus_preproc.la

libsf_modbus_preproc_la_LDFLAGS = -export-dynamic -module @XCCFLAGS@
if SO_WITH_STATIC_LIB
libsf_modbus_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
if BUILD_SNORT_RELOAD
libsf_modbus_preproc_la_LIBADD += ../libsf_dynamic_utils.la
endif
else
nodist_libsf_modbus_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c \
../include/mempool.c \
../include/sf_sdlist.c 
if BUILD_SNORT_RELOAD
nodist_libsf_modbus_preproc_la_SOURCES += ../include/appdata_adjuster.c ../include/sfxhash.c ../include/sfhashfcn.c ../include/sfmemcap.c ../include/sfprimetable.c ../include/reg_test.h ../include/reg_test.c
endif
endif

libsf_modbus_preproc_la_SOURCES = \
spp_modbus.c \
spp_modbus.h \
modbus_decode.c \
modbus_decode.h \
modbus_roptions.c \
modbus_roptions.h \
modbus_paf.c \
modbus_paf.h

if BUILD_BUFFER_DUMP
libsf_modbus_preproc_la_SOURCES += \
modbus_buffer_dump.c \
modbus_buffer_dump.h
endif

EXTRA_DIST = \
sf_modbus.dsp

all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-dynamicpreprocessorLTLIBRARIES

