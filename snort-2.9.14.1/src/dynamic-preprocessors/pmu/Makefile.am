## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include -I${srcdir}/../libs ${glib_CFLAGS}
dynamicpreprocessordir = ${libdir}/snort_dynamicpreprocessor

dynamicpreprocessor_LTLIBRARIES = libsf_pmu_preproc.la

libsf_pmu_preproc_la_LDFLAGS = -export-dynamic -module @XCCFLAGS@

if SO_WITH_STATIC_LIB
libsf_pmu_preproc_la_LIBADD = ../libsf_dynamic_preproc.la
libsf_pmu_preproc_la_LIBADD += -lglib-2.0
if BUILD_SNORT_RELOAD
libsf_pmu_preproc_la_LIBADD += ../libsf_dynamic_utils.la
libsf_pmu_preproc_la_LIBADD += -lglib-2.0
endif
else
nodist_libsf_pmu_preproc_la_SOURCES = \
../include/sf_dynamic_preproc_lib.c \
../include/sfPolicyUserData.c \
../include/mempool.c \
../include/sf_sdlist.c 
nodist_libsf_pmu_preproc_la_LIBADD = -lglib-2.0
if BUILD_SNORT_RELOAD
nodist_libsf_pmu_preproc_la_SOURCES += ../include/appdata_adjuster.c ../include/sfxhash.c ../include/sfhashfcn.c ../include/sfmemcap.c ../include/sfprimetable.c ../include/reg_test.h ../include/reg_test.c
endif
endif

libsf_pmu_preproc_la_SOURCES = \
spp_pmu.c \
spp_pmu.h \
pmu_decode.c \
pmu_decode.h \
pmu_paf.c \
pmu_paf.h 


EXTRA_DIST = \
sf_pmu.dsp

all-local: $(LTLIBRARIES)
	$(MAKE) DESTDIR=`pwd`/../build install-dynamicpreprocessorLTLIBRARIES

