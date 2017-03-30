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
static ACVP_RESULT acvp_des_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp);
static ACVP_RESULT acvp_des_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_ct,
                                    unsigned char *j_iv,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
                                    ACVP_CIPHER alg_id,
				    ACVP_SYM_CIPH_DIR dir);
static ACVP_RESULT acvp_des_release_tc(ACVP_SYM_CIPHER_TC *stc);




static unsigned char old_iv[8];
static unsigned char ptext[10001][8];
static unsigned char ctext[10001][8];

/*
 * After each encrypt/decrypt for a Monte Carlo test the iv
 * and/or pt/ct information may need to be modified.  This function
 * performs the iteration depdedent upon the cipher type and direction.
 */
static ACVP_RESULT acvp_des_mct_iterate_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, 
                                           int i, JSON_Object *r_tobj)
{
    int j = stc->mct_index;
    int n;

    memcpy(ctext[j], stc->ct, stc->ct_len);
    memcpy(ptext[j], stc->pt, stc->pt_len);

    switch (stc->cipher)
    {
    case ACVP_TDES_CBC:
    case ACVP_TDES_OFB:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
    	    if (j == 0) {
	        memcpy(stc->pt, old_iv, 8);
            } else {
	        for(n=0 ; n < 8 ; ++n) {
		    stc->pt[n] = ctext[j-1][n];
	        }
            }
            for(n=0 ; n < 8 ; ++n) {
	        stc->iv[n] = ctext[j][n];
	    }
        } else {
     	    for(n=0 ; n < 8 ; ++n) {
	        stc->ct[n] = ptext[j][n];
	    }
    	    if (j != 0) {
                for(n=0 ; n < 8 ; ++n) {
	            stc->iv[n] = ptext[j-1][n];
		}
	    }
	}
	break;
    case ACVP_TDES_CFB1:
    case ACVP_TDES_CFB8:
    case ACVP_TDES_CFB64:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
    	    if (j == 0) {
	        memcpy(stc->pt, old_iv, 8);
            } else {
	        for(n=0 ; n < 8 ; ++n) {
		    stc->pt[n] = ctext[j-1][n];
	        }
            }
            for(n=0 ; n < 8 ; ++n) {
	        stc->iv[n] = ctext[j][n];
	    }
        } else {

	    for(n=0 ; n < 8 ; ++n) {
		stc->ct[n] ^= stc->pt[n];
	    }
            for(n=0 ; n < 8 ; ++n) {
                stc->iv[n] = stc->pt[n] ^ stc->ct[n];
	    }
        } 
        break;
    case ACVP_TDES_ECB:
        if (stc->direction == ACVP_DIR_ENCRYPT) {
            memcpy(stc->pt, stc->ct, stc->ct_len);
        } else {
            memcpy(stc->ct, stc->pt, stc->pt_len);
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
static ACVP_RESULT acvp_des_output_mct_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, 
                                          JSON_Object *r_tobj)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_des_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
    rv = acvp_bin_to_hexstr(stc->key, stc->key_len/8, (unsigned char*)tmp);
    if (rv != ACVP_SUCCESS) {
	acvp_log_msg(ctx, "hex conversion failure (key)");
	return rv;
    }
    json_object_set_string(r_tobj, "key", tmp);

    if (stc->cipher != ACVP_TDES_ECB) {
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

static const unsigned char odd_parity[256]={
  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};

void acvp_des_set_odd_parity(unsigned char *key)
{
    unsigned int i;

    for (i=0; i<24; i++)
	(key)[i] = odd_parity[(key)[i]];
}



/*
 * This is the handler for DES MCT values.  This will parse
 * a JSON encoded vector set for DES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
static ACVP_RESULT acvp_des_mct_tc(ACVP_CTX *ctx, ACVP_CAPS_LIST *cap, 
		                   ACVP_TEST_CASE *tc, ACVP_SYM_CIPHER_TC *stc, 
				   JSON_Array *res_array)
{
    int i, j, n;
    ACVP_RESULT rv;
    JSON_Value          *r_tval = NULL; /* Response testval */
    JSON_Object         *r_tobj = NULL; /* Response testobj */
    char *tmp;

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_des_output_tc");
        return ACVP_MALLOC_FAIL;
    }


    for (i = 0; i < 400; ++i) {

        /*
         * Create a new test case in the response
         */
        r_tval = json_value_init_object();
        r_tobj = json_value_get_object(r_tval);

        /*
         * Output the test case request values using JSON
         */
        rv = acvp_des_output_mct_tc(ctx, stc, r_tobj);
	if (rv != ACVP_SUCCESS) {
            acvp_log_msg(ctx, "ERROR: JSON output failure in DES module");
            return rv;
        }

	for (j = 0; j < 10000; ++j) {

	    if (j == 0) {
	        memcpy(old_iv, stc->iv, stc->iv_len);
            }
	    stc->mct_index = j;    /* indicates init vs. update */
            /* Process the current DES encrypt test vector... */
            rv = (cap->crypto_handler)(tc);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }
            /*
	     * Adjust the parameters for next iteration if needed.
	     */
	    rv = acvp_des_mct_iterate_tc(ctx, stc, i, r_tobj);
	    if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: Failed the MCT iteration changes");
                return rv;
	    }
        }

	j = 9999;
	if (stc->direction == ACVP_DIR_ENCRYPT) {
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[n] ^= ctext[j][n];
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[8+n] ^= ctext[j-1][n];
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[16+n] ^= ctext[j-2][n];

#if 0   /* TODO: Do we really need to special case 2-key ? */
	if(numkeys == 2)
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[n+16] = stc->key[n];
#endif

  	    acvp_des_set_odd_parity(stc->key);
        } else {
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[n] ^= ptext[j][n];
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[8+n] ^= ptext[j-1][n];
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[16+n] ^= ptext[j-2][n];

#if 0   /* TODO: Do we really need to special case 2-key ? */
	if(numkeys == 2)
	    for(n=0 ; n < 8 ; ++n)
	        stc->key[n+16] = stc->key[n];
#endif

  	    acvp_des_set_odd_parity(stc->key);

        }
	if (stc->direction == ACVP_DIR_ENCRYPT) {

	    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	    rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
	        acvp_log_msg(ctx, "hex conversion failure (ct)");
		return rv;
	    }
	    json_object_set_string(r_tobj, "ct", tmp);


	} else {

	    memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	    rv = acvp_bin_to_hexstr(stc->pt, stc->pt_len, (unsigned char*)tmp);
	    if (rv != ACVP_SUCCESS) {
	        acvp_log_msg(ctx, "hex conversion failure (pt)");
		return rv;
	    }
	    json_object_set_string(r_tobj, "pt", tmp);

        }
        /* Append the test response value to array */
        json_array_append_value(res_array, r_tval);

    }


    free(tmp);

    return ACVP_SUCCESS;
}

/*
 * This is the handler for 3DES values.  This will parse
 * a JSON encoded vector set for 3DES.  Each test case is
 * parsed, processed, and a response is generated to be sent
 * back to the ACV server by the transport layer.
 */
ACVP_RESULT acvp_des_kat_handler(ACVP_CTX *ctx, JSON_Object *obj)
{
    unsigned int tc_id, keylen, ivlen, ptlen;
    unsigned char *     key, *pt = NULL, *ct = NULL, *iv = NULL;
    JSON_Value *        groupval;
    JSON_Object         *groupobj = NULL;
    JSON_Value          *testval;
    JSON_Object         *testobj = NULL;
    JSON_Array          *groups;
    JSON_Array          *tests;
    JSON_Array          *res_tarr = NULL; /* Response resultsArray */
    int i, g_cnt;
    int j, t_cnt;
    JSON_Object         *r_vs = NULL;
    JSON_Array          *r_tarr = NULL; /* Response testarray */
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
     * verify the direction is valid - version 0.2 only
     */
    if (!strncmp(dir_str, "encrypt", 7)) {
	dir = ACVP_DIR_ENCRYPT;
    } else if (!strncmp(dir_str, "decrypt", 7)) {
	dir = ACVP_DIR_DECRYPT;
    } else {
        acvp_log_msg(ctx, "ERROR: unsupported direction requested from server (%s)", dir_str);
        //return (ACVP_UNSUPPORTED_OP);
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.symmetric = &stc;

    /*
     * Get the crypto module handler for DES mode
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
     * Start to build the JSON response
     * TODO: This code will likely be common to all the algorithms, need to move this
     */
    if (ctx->kat_resp) {
        json_value_free(ctx->kat_resp);
    }
    ctx->kat_resp = json_value_init_object();
    r_vs = json_value_get_object(ctx->kat_resp);
    json_object_set_string(r_vs, "acvVersion", ACVP_VERSION);
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
        test_type = (unsigned int)json_object_get_number(groupobj, "testType");

        acvp_log_msg(ctx, "    Test group: %d", i);
        acvp_log_msg(ctx, "        keylen: %d", keylen);
        acvp_log_msg(ctx, "         ivlen: %d", ivlen);
        acvp_log_msg(ctx, "         ptlen: %d", ptlen);
        acvp_log_msg(ctx, "         dir:   %s", dir_str);
        acvp_log_msg(ctx, "      testtype: %d", test_type);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            acvp_log_msg(ctx, "Found new 3DES test vector...");
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
            }

            acvp_log_msg(ctx, "        Test case: %d", j);
            acvp_log_msg(ctx, "            tcId: %d", tc_id);
            acvp_log_msg(ctx, "              key: %s", key);
            acvp_log_msg(ctx, "               pt: %s", pt);
            acvp_log_msg(ctx, "               ct: %s", ct);
            acvp_log_msg(ctx, "               iv: %s", iv);

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
            acvp_des_init_tc(ctx, &stc, tc_id, key, pt, ct, iv,  
		             keylen, ivlen, ptlen, alg_id, dir);

	    /* If Monte Carlo start that here */
	    if (test_type == ACVP_SYM_TEST_TYPE_MCT) {
	        json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
		res_tarr = json_object_get_array(r_tobj, "resultsArray");
	        rv = acvp_des_mct_tc(ctx, cap, &tc, &stc, res_tarr);
		if (rv != ACVP_SUCCESS) {
		    acvp_log_msg(ctx, "ERROR: crypto module failed the DES MCT operation");
		    return ACVP_CRYPTO_MODULE_FAIL;
                }

            } else {

            /* Process the current DES encrypt test vector... */
            rv = (cap->crypto_handler)(&tc);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: crypto module failed the operation");
                return ACVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = acvp_des_output_tc(ctx, &stc, r_tobj);
            if (rv != ACVP_SUCCESS) {
                acvp_log_msg(ctx, "ERROR: JSON output failure in 3DES module");
                return rv;
            }
	}

            /*
             * Release all the memory associated with the test case
             */
            acvp_des_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
    }

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
static ACVP_RESULT acvp_des_output_tc(ACVP_CTX *ctx, ACVP_SYM_CIPHER_TC *stc, JSON_Object *tc_rsp)
{
    ACVP_RESULT rv;
    char *tmp;

    tmp = calloc(1, ACVP_SYM_CT_MAX);
    if (!tmp) {
        acvp_log_msg(ctx, "Unable to malloc in acvp_des_output_tc");
        return ACVP_MALLOC_FAIL;
    }

    if (stc->direction == ACVP_DIR_ENCRYPT) {
	rv = acvp_bin_to_hexstr(stc->iv, stc->iv_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (iv)");
	    return rv;
	}
	json_object_set_string(tc_rsp, "iv", tmp);

	memset(tmp, 0x0, ACVP_SYM_CT_MAX);
	rv = acvp_bin_to_hexstr(stc->ct, stc->ct_len, (unsigned char*)tmp);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "hex conversion failure (ct)");
	    return rv;
	}
	json_object_set_string(tc_rsp, "ct", tmp);
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
 * This function is used to fill-in the data for a 3DES
 * test case.  The JSON parsing logic invokes this after the
 * plaintext, key, etc. have been parsed from the vector set.
 * The ACVP_SYM_CIPHER_TC struct will hold all the data for
 * a given test case, which is then passed to the crypto
 * module to perform the actual encryption/decryption for
 * the test case.
 */
static ACVP_RESULT acvp_des_init_tc(ACVP_CTX *ctx,
                                    ACVP_SYM_CIPHER_TC *stc,
                                    unsigned int tc_id,
                                    unsigned char *j_key,
                                    unsigned char *j_pt,
                                    unsigned char *j_ct,
                                    unsigned char *j_iv,
                                    unsigned int key_len,
                                    unsigned int iv_len,
                                    unsigned int pt_len,
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
    stc->iv = calloc(1, ACVP_SYM_IV_MAX);
    if (!stc->iv) return ACVP_MALLOC_FAIL;

    rv = acvp_hexstr_to_bin((const unsigned char *)j_key, stc->key, ACVP_SYM_KEY_MAX);
    if (rv != ACVP_SUCCESS) {
        acvp_log_msg(ctx, "Hex converstion failure (key)");
        return rv;
    }

    if (j_pt) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_pt, stc->pt, ACVP_SYM_PT_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex converstion failure (pt)");
	    return rv;
	}
    }

    if (j_ct) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_ct, stc->ct, ACVP_SYM_CT_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex converstion failure (ct)");
	    return rv;
	}
    }

    if (j_iv) {
	rv = acvp_hexstr_to_bin((const unsigned char *)j_iv, stc->iv, ACVP_SYM_IV_MAX);
	if (rv != ACVP_SUCCESS) {
	    acvp_log_msg(ctx, "Hex converstion failure (iv)");
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

    stc->cipher = alg_id;
    stc->direction = dir;

    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_des_release_tc(ACVP_SYM_CIPHER_TC *stc)
{
    free(stc->key);
    free(stc->pt);
    free(stc->ct);
    free(stc->iv);
    memset(stc, 0x0, sizeof(ACVP_SYM_CIPHER_TC));

    return ACVP_SUCCESS;
}
