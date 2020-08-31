/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"

int counter_set = 0;
int counter_fail = 0;

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
ACVP_RESULT progress(char *msg)
{
    printf("%s", msg);
    return ACVP_SUCCESS;
}

void teardown_ctx(ACVP_CTX **ctx) {
    acvp_cleanup(*ctx);
}

void setup_empty_ctx (ACVP_CTX **ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    
    rv = acvp_create_test_session(ctx, &progress, level);
    cr_assert(rv == ACVP_SUCCESS);
    
    return;
}

int dummy_handler_success(ACVP_TEST_CASE *test_case) {
    return 0;
}

int dummy_handler_failure(ACVP_TEST_CASE *test_case) {
    if (counter_set == counter_fail) {
        return 1;
    }
    counter_set++;
    return 0;
}

/*
 * get JSON Object from response
 */
JSON_Object *ut_get_obj_from_rsp (JSON_Value *arry_val) {
    JSON_Object *obj = NULL;
    JSON_Array *reg_array;

    reg_array = json_value_get_array(arry_val);
    obj = json_array_get_object(reg_array, 1);
    cr_assert(obj != NULL);
    return (obj);
}


/* This is a public domain base64 implementation written by WEI Zhicheng. */

enum {BASE64_OK = 0, BASE64_INVALID};

#define BASE64_ENCODE_OUT_SIZE(s)    (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)    (((s)) / 4 * 3)

#define BASE64_PAD    '='


#define BASE64DE_FIRST    '+'
#define BASE64DE_LAST    'z'
/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
        /* '+', ',', '-', '.', '/', '0', '1', '2', */
        62,  -1,  -1,  -1,  63,  52,  53,  54,
        
        /* '3', '4', '5', '6', '7', '8', '9', ':', */
        55,  56,  57,  58,  59,  60,  61,  -1,
        
        /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
        -1,  -1,  -1,  -1,  -1,  -1,   0,   1,
        
        /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
        2,   3,   4,   5,   6,   7,   8,   9,
        
        /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
        10,  11,  12,  13,  14,  15,  16,  17,
        
        /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
        18,  19,  20,  21,  22,  23,  24,  25,
        
        /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
        -1,  -1,  -1,  -1,  -1,  -1,  26,  27,
        
        /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
        28,  29,  30,  31,  32,  33,  34,  35,
        
        /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
        36,  37,  38,  39,  40,  41,  42,  43,
        
        /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
        44,  45,  46,  47,  48,  49,  50,  51,
};

unsigned int base64_decode(const char *in, unsigned int inlen, unsigned char *out)
{
    unsigned int i, j;
    
    for (i = j = 0; i < inlen; i++) {
        int c;
        int s = i % 4;             /* from 8/gcd(6, 8) */
        
        if (in[i] == '=')
            return j;
        
        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST ||
            (c = base64de[in[i] - BASE64DE_FIRST]) == -1)
            return 0;
        
        switch (s) {
        case 0:
            out[j] = ((unsigned int)c << 2) & 0xFF;
            continue;
        case 1:
            out[j++] += ((unsigned int)c >> 4) & 0x3;
            
            /* if not last char with padding */
            if (i < (inlen - 3) || in[inlen - 2] != '=')
                out[j] = ((unsigned int)c & 0xF) << 4;
            continue;
        case 2:
            out[j++] += ((unsigned int)c >> 2) & 0xF;
            
            /* if not last char with padding */
            if (i < (inlen - 2) || in[inlen - 1] != '=')
                out[j] =  ((unsigned int)c & 0x3) << 6;
            continue;
        case 3:
            out[j++] += (unsigned char)c;
        }
    }
    
    return j;
}

unsigned int dummy_totp(char **token, int token_max) {
    memset_s((char *)*token, token_max, '0', token_max);
    return 0;
}


