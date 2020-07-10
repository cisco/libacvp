ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

dist_data_DATA = README.md
EXTRA_DIST = ms docker certs scripts docs metadata murl

if UNIT_TEST_SUPPORTED
TEST_DIR=test
endif


if APP_NOT_SUPPORTED
APP_DIR=
else
APP_DIR=app
endif

if LIB_NOT_SUPPORTED
LIB_DIR=
else
LIB_DIR=src
endif

SUBDIRS = safe_c_stub $(LIB_DIR) $(APP_DIR) $(TEST_DIR)

