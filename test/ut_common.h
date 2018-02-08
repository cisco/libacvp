#include <string.h>
#include <stdio.h>
#include <criterion/criterion.h>
#include "acvp.h"

void teardown_ctx(ACVP_CTX **ctx);
ACVP_RESULT progress(char *msg);
ACVP_RESULT test_sha_handler(ACVP_TEST_CASE *tc);