## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libdpx.la

libdpx_la_LDFLAGS = -export-dynamic

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c

nodist_libdpx_la_SOURCES = \
sf_dynamic_preproc_lib.c \
sfPolicyUserData.c

libdpx_la_SOURCES = \
dpx.c \
sf_preproc_info.h

sf_dynamic_preproc_lib.c: ${SOURCE}/sf_dynamic_preproc_lib.c
	cp $? $@

sfPolicyUserData.c: ${SOURCE}/sfPolicyUserData.c
	cp $? $@

clean-local:
	rm -f sf_dynamic_preproc_lib.c sfPolicyUserData.c
