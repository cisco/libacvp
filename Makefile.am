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

SUBDIRS = safe_c_stub src $(APP_DIR) $(TEST_DIR)
DIST_SUBDIRS = safe_c_stub src $(APP_DIR) $(TEST_DIR)

