ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

dist_data_DATA = README.md
EXTRA_DIST = ms docker certs scripts docs metadata murl

if UNIT_TEST_SUPPORTED
TEST_DIR=test
endif

SUBDIRS = safe_c_stub src app $(TEST_DIR)

