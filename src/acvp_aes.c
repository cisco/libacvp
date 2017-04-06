/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification, 
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, 
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation 
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acvp.h"
#include "acvp_lcl.h"
#include "parson.h"

/*
 * Forward prototypes for local functions
 */
static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp);
static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    ACVP_SYM_CIPH_TESTTYPE test_type,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_ct,
                                    unsigned char *j_iv,
                                    unsigned char *j_tag,
                                    unsigned char *j_aad,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
                                    unsigned int aad_len,
                                    unsigned int tag_len,
                                    ACVP_CIPHER alg_id,
				    ACVP_SYM_CIPH_DIR dir);
static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc);


static unsigned char key[101][32];
static unsigned char iv[101][16];
static unsigned char ptext[1001][32];
static unsigned char ctext[1001][32];
 
#define gb(a,b) (((a)[(b)/8] >> (7-(b)%8))&1)
#define sb(a,b,v) ((a)[(b)/8]=((a)[(b)/8]&~(1 << (7-(b)%8)))|(!!(v) << (7-(b)%8)))

/*
 * After each encrypt/decrypt for a Monte Carlo test the iv
 * and/or pt/ct information may need to be modified.  This function
 * performs the iteration depdedent upon the cipher type and direction.
 */
static ACVP_RESULT acvp_aes_mct_iterate_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, int i)
{
    int n1, n2;
    int j = stc->mct_index;


    memcpy(ctext[j], stc->ct, stc->ct_len);
    memcpy(ptext[j], stc->pt, stc->pt_len);
    if (j == 0) {
        memcpy(key[j], stc->key, stc->key_len/8);
    }

    switch (stc->cipher)
    {
    case ACVP_AES_ECB:

        if (stc->direction == ACVP_DIR_ENCRYPT) {
            memcpy(stc->pt, ctext[j], stc->ct_len);
        } else {
           memcpy(stc->ct, ptext[j], stc->ct_len);
        }
	break;

    case ACVP_AES_CBC:
    case ACVP_AES_OFB:
    case ACVP_AES_CFB128:
	if (j == 0) {
	    memcpy(stc->pt, stc->iv, stc->ct_len);
	} else {

            if (stc->direction == ACVP_DIR_ENCRYPT) {
                memcpy(stc->pt, ctext[j-1], stc->ct_len);
                memcpy(stc->iv, ctext[j], stc->ct_len);
            } else {
                memcpy(stc->ct, ptext[j-1], stc->ct_len);
                memcpy(stc->iv, ptext[j], stc->ct_len);
            }
	}
	break;

    case ACVP_AES_CFB8:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
		/* IV[i+1] = ct */
		for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2)
		    iv[i+1][n1] = ctext[j-n2][0];
		ptext[0][0] = ctext[j-16][0];
	} else {
		for (n1 = 0, n2 = 15; n1 < 16; ++n1, --n2)
		    iv[i+1][n1] = ptext[j-n2][0];
		ctext[0][0] = ptext[j-16][0];
        }
	break;

    case ACVP_AES_CFB1:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
		for(n1=0,n2=127 ; n1 < 128 ; ++n1,--n2)
		    sb(iv[i+1],n1,gb(ctext[j-n2],0));
		ptext[0][0]=ctext[j-128][0]&0x80;
        } else {
		for(n1=0,n2=127 ; n1 < 128 ; ++n1,--n2)
		    sb(iv[i+1],n1,gb(ptext[j-n2],0));
		ctext[0][0]=ptext[j-128][0]&0x80;
        }
	break;
    default:
        break;
    }    

    return ACVP_SUCCESS;
}


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case for MCT.
 */
static ACVP_RESULT acvp_aes_output_mct_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *r_tobj)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->key, stc->key_len/8, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
	acvp_log_msg(ctx, "hex conversion failure (key)");
	return rv;
    }
    json_object_set_string(r_tobj, "key", tmp);

    if (stc->cipher != ACVP_AES_ECB) {
        memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (iv)");
	    return rv;
        }
        json_object_set_string(r_tobj, "iv", tmp);
    }

    if (stc->direction == ACVP_DIR_ENCRYPT) {
	memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (pt)");
	    return rv;
	}
	json_object_set_string(r_tobj, "pt", tmp);

    } else {
	memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (ct)");
	    return rv;
	}
	json_object_set_string(r_tobj, "ct", tmp);
    }

    free(tmp);

    return ACVP_SUCCESS;
}


/*
 * This is the handler for AES MCT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
static ACVP_RESULT acvp_aes_mct_tc(ACVP_CTX *ctx, ACVP_CAPS_LIST *cap, 
		                   ACVP_TEST_CASE *tc, ACVP_SYM_CIPHER_TC *stc, 
				   JSON_Array *res_array)
{
    int i, j, n, n1, n2;
    ACVP_RESULT rv;
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    char *tmp;
    unsigned char ciphertext[64+4];

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }


    for (i = 0; i < 100; ++i) {

        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /*
         * Output the test case request values using JSON
         */
        rv = acvp_aes_output_mct_tc(ctx, stc, r_tobj);
	if (rv != ACVP_SUCCESS) {
            acvp_log_msg(ctx, "ERROR: JSON output failure in AES module");
            return rv;
        }

	for (j = 0; j < 1000; ++j) {

	    stc->mct_index = j;    /* indicates init vs. update */
            /* Process the current AES encrypt test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
	     * Adjust the parameters for next iteration if needed.
	     */
	    rv = acvp_aes_mct_iterate_tc(ctx, stc, i);
	    if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: Failed the MCT iteration changes");
                return rv;
	    }
        }

	j = 999;
	if (stc->direction == ACVP_DIR_ENCRYPT) {

	    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	    rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
	        acvp_log_msg(ctx, "hex conversion failure (ct)");
		return rv;
	    }
	    json_object_set_string(r_tobj, "ct", tmp);

	    switch (stc->key_len)
	    {
	    case 128:
	        memcpy(ciphertext, ctext[j], 16);
		break;
	    case 192:
	        memcpy(ciphertext, ctext[j-1]+8, 8);
		memcpy(ciphertext+8, ctext[j], 16);
		break;
	    case 256:
	        memcpy(ciphertext, ctext[j-1], 16);
	        memcpy(ciphertext+16, ctext[j], 16);
	        break;
            }

            if (stc->cipher == ACVP_AES_CFB8)
		{ /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
		for (n1 = 0, n2 = stc->key_len/8-1; n1 < stc->key_len/8; ++n1, --n2)
		    ciphertext[n1] = ctext[j-n2][0];
		}
            if (stc->cipher == ACVP_AES_CFB1)
		{
		for(n1=0,n2=stc->key_len-1 ; n1 < stc->key_len ; ++n1,--n2)
		    sb(ciphertext,n1,gb(ctext[j-n2],0));
		}

	} else {

	    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	    rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
	        acvp_log_msg(ctx, "hex conversion failure (pt)");
		return rv;
	    }
	    json_object_set_string(r_tobj, "pt", tmp);

	    switch (stc->key_len)
	    {
	    case 128:
	        memcpy(ciphertext, ptext[j], 16);
		break;
	    case 192:
	        memcpy(ciphertext, ptext[j-1]+8, 8);
		memcpy(ciphertext+8, ptext[j], 16);
		break;
	    case 256:
	        memcpy(ciphertext, ptext[j-1], 16);
		memcpy(ciphertext+16, ptext[j], 16);
		break;
            }
	    if (stc->cipher == ACVP_AES_CFB8)
		{ /* ct = CT[j-15] || CT[j-14] || ... || CT[j] */
		for (n1 = 0, n2 = stc->key_len/8-1; n1 < stc->key_len/8; ++n1, --n2)
		    ciphertext[n1] = ptext[j-n2][0];
		}
	    if (stc->cipher == ACVP_AES_CFB1)
		{
		for(n1=0,n2=stc->key_len-1 ; n1 < stc->key_len ; ++n1,--n2)
		    sb(ciphertext,n1,gb(ptext[j-n2],0));
		}

        }


	/* create the key for the next loop */
        for (n = 0; n < stc->key_len/8; ++n)
	    stc->key[n] = key[0][n] ^ ciphertext[n];

        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);

    }


    free(tmp);

    return ACVP_SUCCESS;
}


/*
 * This is the handler for AES KAT values.  This will parse
 * a JSON encoded vector set for AES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
ACVP_RESULT acvp_aes_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int tc_id, keylen, ivlen, ptlen, aadlen, taglen;
    unsigned char *     key, *pt = NULL, *ct = NULL, *aad = NULL, *iv = NULL, *tag = NULL;
    JSON_Value *        groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;

    JSON_Value          *reg_arry_val  = NULL;
    JSON_Object         *reg_obj       = NULL;
    JSON_Array          *reg_arry      = NULL;

    int i, g_cnt;
    int j, t_cnt;
    JSON_Value          *r_vs_val = NULL;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
    JSON_Array          *res_tarr = NULL; /* Response resultsArray */
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    ACVP_CAPS_LIST      *cap;
    ACVP_SYM_CIPHER_TC stc;
    ACVP_TEST_CASE tc;
    ACVP_RESULT rv;
    const char		*dir_str = json_object_get_string(obj, "direction"); 
    const char		*alg_str = json_object_get_string(obj, "algorithm"); 
    ACVP_SYM_CIPH_DIR	dir;
    ACVP_CIPHER	alg_id;
    ACVP_SYM_CIPH_TESTTYPE test_type;

    if (!alg_str) {
        acvp_log_msg(ctx, "ERROR: unable to parse 'algorithm' from JSON");
	return (ACVP_MALFORMED_JSON);
    }

    /*
     * verify the direction is valid - 0.2 version only
     */
    if (dir_str != NULL) {
        if (!strncmp(dir_str, "encrypt", 7)) {
	    dir = ACVP_DIR_ENCRYPT;
        } else if (!strncmp(dir_str, "decrypt", 7)) {
	    dir = ACVP_DIR_DECRYPT;
        } else {
            acvp_log_msg(ctx, "ERROR: unsupported direction requested from server (%s)", dir_str);
            //return (ACVP_UNSUPPORTED_OP);
        }
    }
    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.symmetric = &stc;

    /*
     * Get the crypto module handler for AES mode
     */
    alg_id = acvp_lookup_cipher_index(alg_str);
    if (alg_id < ACVP_CIPHER_START) {
        acvp_log_msg(ctx, "ERROR: unsupported algorithm (%s)", alg_str);
        return (ACVP_UNSUPPORTED_OP);
    }
    cap = acvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        acvp_log_msg(ctx, "ERROR: ACVP server requesting unsupported capability");
        return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Create ACVP array for response
     */
    rv = acvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "ERROR: Failed to create JSON response struct. ");
        return(rv);
    }

    /*
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = reg_arry_val;
    r_vs_val = json_value_init_object();
    r_vs = json_value_get_object(r_vs_val);
    json_object_set_number(r_vs, "vsId", ctx->vs_id);
    json_object_set_string(r_vs, "algorithm", alg_str);
    if (dir_str != NULL)
        json_object_set_string(r_vs, "direction", dir_str); 
    json_object_set_value(r_vs, "testResults", json_value_init_array());
    r_tarr = json_object_get_array(r_vs, "testResults");

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

	/* version 0.3 direction */
	if (dir_str == NULL) {
            dir_str = json_object_get_string(groupobj, "direction");
    	    /*
    	     * verify the direction is valid 
     	     */
    	    if (!strncmp(dir_str, "encrypt", 7)) {
	        dir = ACVP_DIR_ENCRYPT;
    	    } else if (!strncmp(dir_str, "decrypt", 7)) {
	        dir = ACVP_DIR_DECRYPT;
    	    } else {
                acvp_log_msg(ctx, "ERROR: unsupported direction requested from server (%s)", dir_str);
                return (ACVP_UNSUPPORTED_OP);
            }
        }
        keylen = (unsigned int)json_object_get_number(groupobj, "keyLen");
        ivlen = (unsigned int)json_object_get_number(groupobj, "ivLen");
        ptlen = (unsigned int)json_object_get_number(groupobj, "ptLen");
        aadlen = (unsigned int)json_object_get_number(groupobj, "aadLen");
        taglen = (unsigned int)json_object_get_number(groupobj, "tagLen");
        test_type = (unsigned int)json_object_get_number(groupobj, "testType");

        acvp_log_msg(ctx, "    Test group: %d", i);
        acvp_log_msg(ctx, "        keylen: %d", keylen);
        acvp_log_msg(ctx, "         ivlen: %d", ivlen);
        acvp_log_msg(ctx, "         ptlen: %d", ptlen);
        acvp_log_msg(ctx, "        aadlen: %d", aadlen);
        acvp_log_msg(ctx, "        taglen: %d", taglen);
        acvp_log_msg(ctx, "         dir:   %s", dir_str);
        acvp_log_msg(ctx, "      testtype: %d", test_type);


        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            acvp_log_msg(ctx, "Found new AES test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = (unsigned int)json_object_get_number(testobj, "tcId");
            key = (unsigned char *)json_object_get_string(testobj, "key");
	    if (dir == ACVP_DIR_ENCRYPT) { 
		pt = (unsigned char *)json_object_get_string(testobj, "pt");
		iv = (unsigned char *)json_object_get_string(testobj, "iv");
            } else {
		ct = (unsigned char *)json_object_get_string(testobj, "ct");
		iv = (unsigned char *)json_object_get_string(testobj, "iv");
		tag = (unsigned char *)json_object_get_string(testobj, "tag");
            }
            aad = (unsigned char *)json_object_get_string(testobj, "aad");

            acvp_log_msg(ctx, "        Test case: %d", j);
            acvp_log_msg(ctx, "            tcId: %d", tc_id);
            acvp_log_msg(ctx, "              key: %s", key);
            acvp_log_msg(ctx, "               pt: %s", pt);
            acvp_log_msg(ctx, "               ct: %s", ct);
            acvp_log_msg(ctx, "               iv: %s", iv);
            acvp_log_msg(ctx, "              tag: %s", tag);
            acvp_log_msg(ctx, "              aad: %s", aad);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             * TODO: this does mallocs, we can probably do the mallocs once for
             *       the entire vector set to be more efficient
             */
            acvp_aes_init_tc(ctx, &stc, tc_id, test_type, key, pt, ct, iv, tag, aad, 
		             keylen, ivlen, ptlen, aadlen, taglen, alg_id, dir);

	    /* If Monte Carlo start that here */
	    if (test_type == ACVP_SYM_TEST_TYPE_MCT) {
	        json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
		res_tarr = json_object_get_array(r_tobj, "resultsArray");
	        rv = acvp_aes_mct_tc(ctx, cap, &tc, &stc, res_tarr);
		if (rv != ACVP_SUCCESS) {
		    acvp_log_msg(ctx, "ERROR: crypto module failed the MCT operation");
		    return ACVP_CRYPTO_MODULE_FAIL;
                }

            } else {

                /* Process the current AES KAT test vector... */
		rv = (cap->crypto_handler)(&tc);
		if (rv != ACVP_SUCCESS) {
		    acvp_log_msg(ctx, "ERROR: crypto module failed the operation");
		    return ACVP_CRYPTO_MODULE_FAIL;
                }

                /*
		 * Output the test case results using JSON
		 */
		rv = acvp_aes_output_tc(ctx, &stc, r_tobj);
		if (rv != ACVP_SUCCESS) {
                    acvp_log_msg(ctx, "ERROR: JSON output failure in AES module");
                    return rv;
                }
	    }

            /*
             * Release all the memory associated with the test case
             */
            acvp_aes_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }
    json_array_append_value(reg_arry, r_vs_val);

    //FIXME
    printf("\n\n%s\n\n", json_serialize_to_string_pretty(ctx->kat_resp));

    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_aes_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_aes_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->direction == ACVP_DIR_ENCRYPT) {
	/*
	 * Keywrap doesn't use an IV
	 */
	if (stc->cipher != ACVP_AES_KW) {
	    rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
		acvp_log_msg(ctx, "hex conversion failure (iv)");
		return rv;
	    }
	    json_object_set_string(tc_rsp, "iv", tmp);
	}

	memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (ct)");
	    return rv;
	}
	json_object_set_string(tc_rsp, "ct", tmp);

	/*
	 * AEAD ciphers need to include the tag 
	 */
	if (stc->cipher == ACVP_AES_GCM || stc->cipher == ACVP_AES_CCM) {
	    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	    rv = acvp_bin_to_hexstr(stc->tag, stc->tag_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
		acvp_log_msg(ctx, "hex conversion failure (tag)");
		return rv;
	    }
	    json_object_set_string(tc_rsp, "tag", tmp);
	}
    } else {
	rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (pt)");
	    return rv;
	}
	json_object_set_string(tc_rsp, "pt", tmp);
    }

    free(tmp);

    return ACVP_SUCCESS;
}


/*
 * This function is used to fill-in the data for an AES
 * test case.  The JSON parsing logic invokes this after the
 * plaintext, key, etc. have been parsed from the vector set.
 * The ACVP_SYM_CIPHER_TC struct will hold all the data for
 * a given test case, which is then passed to the crypto
 * module to perform the actual encryption/decryption for
 * the test case.
 */
static ACVP_RESULT acvp_aes_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    ACVP_SYM_CIPH_TESTTYPE test_type,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_ct,
                                    unsigned char *j_iv,
                                    unsigned char *j_tag,
                                    unsigned char *j_aad,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
                                    unsigned int aad_len,
                                    unsigned int tag_len,
                                    ACVP_CIPHER alg_id,
				    ACVP_SYM_CIPH_DIR dir)
{
    ACVP_RESULT rv;

    //FIXME:  check lengths do not exceed MAX values below

    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    stc->key = calloc(1, ACVP_SYM_KEY_MAX);
    if (!stc->key) return ACVP_MALLOC_FAIL;
    stc->pt = calloc(1, ACVP_SYM_PT_MAX);
    if (!stc->pt) return ACVP_MALLOC_FAIL;
    stc->ct = calloc(1, ACVP_SYM_CT_MAX);
    if (!stc->ct) return ACVP_MALLOC_FAIL;
    stc->tag = calloc(1, ACVP_SYM_TAG_MAX);
    if (!stc->tag) return ACVP_MALLOC_FAIL;
    stc->iv = calloc(1, ACVP_SYM_IV_MAX);
    if (!stc->iv) return ACVP_MALLOC_FAIL;
    stc->aad = calloc(1, ACVP_SYM_AAD_MAX);
    if (!stc->aad) return ACVP_MALLOC_FAIL;

    rv = acvp_hexstr_to_bin((const unsigned char *)j_key, stc->key, ACVP_SYM_KEY_MAX);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Hex conversion failure (key)");
        return rv;
    }

    if (j_pt) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_pt, stc->pt, ACVP_SYM_PT_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex conversion failure (pt)");
	    return rv;
	}
    }

    if (j_ct) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_ct, stc->ct, ACVP_SYM_CT_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex conversion failure (ct)");
	    return rv;
	}
    }

    if (j_iv) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_iv, stc->iv, ACVP_SYM_IV_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex conversion failure (iv)");
	    return rv;
	}
    }

    if (j_tag) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_tag, stc->tag, ACVP_SYM_TAG_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex conversion failure (tag)");
	    return rv;
	}
    }

    if (j_aad) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_aad, stc->aad, ACVP_SYM_AAD_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex conversion failure (aad)");
	    return rv;
	}
    }

    /*
     * These lengths come in as bit lengths from the ACVP server.
     * We convert to bytes.
     * TODO: do we need to support bit lengths not a multiple of 8?
     */
    stc->tc_id = tc_id;
    stc->key_len = key_len;
    stc->iv_len = iv_len/8;
    stc->pt_len = pt_len/8;
    stc->ct_len = pt_len/8; 
    stc->tag_len = tag_len/8;
    stc->aad_len = aad_len/8;

    stc->cipher = alg_id;
    stc->direction = dir;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_aes_release_tc(ACVP_SYM_CIPHER_TC *stc)
{
    free(stc->key);
    free(stc->pt);
    free(stc->ct);
    free(stc->tag);
    free(stc->iv);
    free(stc->aad);
    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    return ACVP_SUCCESS;
}
