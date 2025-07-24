/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "app_lcl.h"
#include "safe_lib.h"

//TODO: This shouldn't need to be set
char value[JSON_STRING_LENGTH];

void print_version_info(APP_CONFIG *cfg) {
    printf("\n ACVP library version: %s\n", acvp_version());
    printf("ACVP protocol version: %s\n\n", acvp_protocol_version());
    printf("Implementation Under Test version information:\n\n");

    iut_print_version(cfg);
    printf("\n");
}

int app_setup_two_factor_auth(ACVP_CTX *ctx) {
    ACVP_RESULT rv = 0;

    if (getenv("ACV_TOTP_SEED")) {
        /*
         * Specify the callback to be used for 2-FA to perform
         * TOTP calculation
         */
        rv = acvp_set_2fa_callback(ctx, &totp);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set Two-factor authentication callback\n");
            return 1;
        }
    }

    return 0;
}

unsigned int swap_uint_endian(unsigned int i) {
    int a = 0, b = 0, c = 0, d = 0;
    a = (i >> 24) & 0x000000ff;
    b = (i >> 8) & 0x0000ff00;
    c = (i << 8) & 0x00ff0000;
    d = (i << 24) & 0xff000000;
	return (a | b | c | d);
}

int check_is_little_endian() {
    short int n = 1;
    char *ptr = (char *)&n;
    if (ptr[0] == 1) {
        return 1;
    }
    return 0;
}
char *remove_str_const(const char *str) {
    int len = 0;
    char *ret = NULL;
    len = strnlen_s(str, ALG_STR_MAX_LEN + 1);
    if (len > ALG_STR_MAX_LEN) {
        printf("Alg string too long\n");
        return NULL;
    }

    ret = calloc(len + 1, sizeof(char));
    if (!ret) {
        printf("Error allocating memory when removing const from str\n");
        return NULL;
    }

    if (strncpy_s(ret, len + 1, str, len)) {
        printf("Error copying string to non-const buffer\n");
        free(ret);
        return NULL;
    }

    return ret;
}

int save_string_to_file(const char *str, const char *path) {
    int rv = 1;

    if (!str) {
        return 1;
    }

    FILE *fp = NULL;
    fp = fopen(path, "w");
    if (!fp) {
        return 1;
    }

    if (fputs(str, fp) == EOF) {
        goto end;
    }

    if (fputs("\n", fp) == EOF) {
        goto end;
    }

    rv = 0;
 end:
    if (fp && fclose(fp) == EOF) {
        printf("Encountered an error attempting to close output file. Cannot guarantee file integrity.\n");
    }
    return rv;
}
