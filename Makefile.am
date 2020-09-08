ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

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

##dist_data_DATA includes files to be installed to the /share folder
##SUBDIRS references code that needs to be built and their files only. These files are included in dist.
##EXTRA_DIST is not referenced for building code but for creating the dist and includes NON-code files as well.
dist_data_DATA = README.md
EXTRA_DIST = ms docker certs scripts docs metadata murl test
SUBDIRS = safe_c_stub $(LIB_DIR) $(APP_DIR) $(TEST_DIR)

