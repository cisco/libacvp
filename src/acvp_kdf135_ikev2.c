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
static ACVP_RESULT acvp_kdf135_ikev2_output_tc (ACVP_CTX *ctx, ACVP_KDF135_IKEV2_TC *stc, JSON_Object *tc_rsp);

static ACVP_RESULT acvp_kdf135_ikev2_init_tc (ACVP_CTX *ctx,
                                            ACVP_KDF135_IKEV2_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            unsigned int method,
                                            unsigned int sha,
                                            unsigned int pm_len,
                                            unsigned int kb_len,
                                            const char *pm_secret,
                                            const char *sh_rnd,
                                            const char *ch_rnd,
                                            const char *s_rnd,
                                            const char *c_rnd);

static ACVP_RESULT acvp_kdf135_ikev2_release_tc (ACVP_KDF135_IKEV2_TC *stc);


ACVP_RESULT acvp_kdf135_ikev2_kat_handler (ACVP_CTX *ctx, JSON_Object *obj) {
    return ACVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static ACVP_RESULT acvp_kdf135_ikev2_output_tc (ACVP_CTX *ctx, ACVP_KDF135_IKEV2_TC *stc, JSON_Object *tc_rsp) {

    return ACVP_SUCCESS;
}

static ACVP_RESULT acvp_kdf135_ikev2_init_tc (ACVP_CTX *ctx,
                                            ACVP_KDF135_IKEV2_TC *stc,
                                            unsigned int tc_id,
                                            ACVP_CIPHER alg_id,
                                            unsigned int method,
                                            unsigned int md,
                                            unsigned int pm_len,
                                            unsigned int kb_len,
                                            const char *pm_secret,
                                            const char *sh_rnd,
                                            const char *ch_rnd,
                                            const char *s_rnd,
                                            const char *c_rnd) {
    return ACVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static ACVP_RESULT acvp_kdf135_ikev2_release_tc (ACVP_KDF135_IKEV2_TC *stc) {
    return ACVP_SUCCESS;
}
