/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
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
#include "app_lcl.h"
#include "safe_lib.h"

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

static void print_usage(int err) {
    if (err) {
        printf("\nInvalid usage...\n");
    } else {
        printf("\n===========================");
        printf("\n===== ACVP_APP USAGE ======");
        printf("\n===========================\n");
    }
    printf("This program does not require any argument, however logging level can be\n");
    printf("controlled using:\n");
    printf("      --none\n");
    printf("      --error\n");
    printf("      --warn\n");
    printf("      --status(default)\n");
    printf("      --info\n");
    printf("      --verbose\n");
    printf("      --version\n");
    printf("\n");
    printf("Algorithm Test Suites:\n");
    printf("      --aes(default)\n");
    printf("      --no_aes\n");
    printf("      --tdes(default)\n");
    printf("      --no_tdes\n");
    printf("      --hash(default)\n");
    printf("      --no_hash\n");
    printf("      --cmac(default)\n");
    printf("      --no_cmac\n");
    printf("      --hmac(default)\n");
    printf("      --no_hmac\n");
#ifdef OPENSSL_KDF_SUPPORT
    printf("      --kdf\n");
    printf("      --no_kdf(default)\n");
#endif
#ifdef ACVP_NO_RUNTIME
    printf("      --dsa\n");
    printf("      --no_dsa(default)\n");
    printf("      --rsa\n");
    printf("      --no_rsa(default)\n");
    printf("      --ecdsa\n");
    printf("      --no_ecdsa(default)\n");
    printf("      --drbg\n");
    printf("      --no_drbg(default)\n");
    printf("      --kas_ecc\n");
    printf("      --no_kas_ecc(default)\n");
    printf("      --kas_ffc\n");
    printf("      --no_kas_ffc(default)\n");
#endif
    printf("\n");
    printf("To register a formatted JSON file use:\n");
    printf("      --json <file>\n");
    printf("\n");
    printf("To process kat vectors from a JSON file use:\n");
    printf("      --kat <file>\n");
    printf("\n");
    printf("If you are running a sample registration (querying for correct answers\n");
    printf("in addition to the normal registration flow) use:\n");
    printf("      --sample\n");
    printf("\n");
    printf("If you want to include \"debugRequest\" in your registration, use:\n");
    printf("      --dev\n");
    printf("\n");
    printf("In addition some options are passed to acvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to %s)\n", DEFAULT_URI_PREFIX);
    printf("    ACV_TOTP_SEED (when not set, client will not use Two-factor authentication)\n");
    printf("    ACV_CA_FILE\n");
    printf("    ACV_CERT_FILE\n");
    printf("    ACV_KEY_FILE\n\n");
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n");
}

static int cli_alg_option(int *alg,
                          int *op_status,
                          int enable,
                          char *enable_str,
                          char *disable_str) {
#define OP_DISABLE 1
#define OP_ENABLE 2
    if (enable) {
        /*
         * Trying to enable this algorithm.
         * Check to see if algorithm has been disabled already.
         */
        if (*op_status == OP_DISABLE) {
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nAlgorithm already disabled by \"%s\"."
                   "\nPlease give only 1 of these options at a time.\n",
                   enable_str, disable_str);
            return 1;
        }
        *op_status = OP_ENABLE;
        *alg = 1;
    } else {
        /*
         * Trying to disable this algorithm.
         * Check to see if algorithm has been disabled already.
         */
        if (*op_status == OP_ENABLE) {
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nAlgorithm already enabled by \"%s\"."
                   "\nPlease give only 1 of these options at a time.\n",
                   disable_str, enable_str);
            return 1;
        }
        *op_status = OP_DISABLE;
        *alg = 0;
    }

    return 0;
}

static void default_config(APP_CONFIG *cfg) {
    cfg->level = ACVP_LOG_LVL_STATUS;
    cfg->aes = 1;
    cfg->tdes = 1;
    cfg->hash = 1;
    cfg->cmac = 1;
    cfg->hmac = 1;
}

int ingest_cli(APP_CONFIG *cfg, int argc, char **argv) {
    char *log_lvl = NULL;
    int diff = 0;
    int aes_status = 0, tdes_status = 0,
        hash_status = 0, cmac_status = 0,
        hmac_status = 0;

#ifdef ACVP_NO_RUNTIME
    int dsa_status = 0, rsa_status = 0,
        drbg_status = 0, ecdsa_status = 0,
        kas_ecc_status = 0, kas_ffc_status = 0;
#endif
#ifdef OPENSSL_KDF_SUPPORT
    int kdf_status = 0;
#endif

#define ALG_DISABLE 0
#define ALG_ENABLE 1
#define OPTION_STR_MAX 16

    /* Set the default configuration values */
    default_config(cfg);

    argv++;
    argc--;
    while (argc >= 1) {
        /* version option used by itself, ignore remaining command line */
        strcmp_s("--version", strnlen_s("--version", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            printf("\nACVP library version(protocol version): %s(%s)\n", acvp_version(), acvp_protocol_version());
            return 1;
        }

        strcmp_s("--help", strnlen_s("--help", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            print_usage(0);
            return 1;
        }

        strcmp_s("--info", strnlen_s("--info", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--info", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_INFO;
            log_lvl = "info";
            goto next;
        }

        strcmp_s("--status", strnlen_s("--status", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--status", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_STATUS;
            log_lvl = "status";
            goto next;
        }

        strcmp_s("--warn", strnlen_s("--warn", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--warn", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_WARN;
            log_lvl = "warn";
            goto next;
        }

        strcmp_s("--error", strnlen_s("--error", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--error", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_ERR;
            log_lvl = "error";
            goto next;
        }

        strcmp_s("--none", strnlen_s("--none", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--none", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_NONE;
            log_lvl = "none";
            goto next;
        }

        strcmp_s("--verbose", strnlen_s("--verbose", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (log_lvl) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nLog Level already set to \"%s\"."
                       "\nOnly 1 Log Level can be specified.\n", "--verbose", log_lvl);
                print_usage(1);
                return 1;
            }
            cfg->level = ACVP_LOG_LVL_VERBOSE;
            log_lvl = "verbose";
            goto next;
        }

        strcmp_s("--json", strnlen_s("--json", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            int filename_len = 0;

            cfg->json = 1;
            argc--;
            argv++;

            if (*argv == NULL) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nMissing <file>.\n", "--json");
                print_usage(1);
                return 1;
            }

            filename_len = strnlen_s(*argv, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--json", *argv, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->json_file, JSON_FILENAME_LENGTH + 1, *argv);
            goto next;
        }

        strcmp_s("--kat", strnlen_s("--kat", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            int filename_len = 0;

            cfg->kat = 1;
            argc--;
            argv++;

            if (*argv == NULL) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nMissing <file>.\n", "--kat");
                print_usage(1);
                return 1;
            }

            filename_len = strnlen_s(*argv, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--kat", *argv, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->kat_file, JSON_FILENAME_LENGTH + 1, *argv);
            goto next;
        }

        strcmp_s("--sample", strnlen_s("--sample", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            cfg->sample = 1;
            goto next;
        }

        strcmp_s("--dev", strnlen_s("--dev", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            cfg->dev = 1;
            goto next;
        }

        strcmp_s("--aes", strnlen_s("--aes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->aes, &aes_status, ALG_ENABLE,
                               "--aes", "--no_aes")) return 1;
            goto next;
        }

        strcmp_s("--no_aes", strnlen_s("--no_aes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->aes, &aes_status, ALG_DISABLE,
                               "--aes", "--no_aes")) return 1;
            goto next;
        }

        strcmp_s("--tdes", strnlen_s("--tdes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->tdes, &tdes_status, ALG_ENABLE,
                               "--tdes", "--no_tdes")) return 1;
            goto next;
        }

        strcmp_s("--no_tdes", strnlen_s("--no_tdes", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->tdes, &tdes_status, ALG_DISABLE,
                               "--tdes", "--no_tdes")) return 1;
            goto next;
        }

        strcmp_s("--hash", strnlen_s("--hash", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hash, &hash_status, ALG_ENABLE,
                               "--hash", "--no_hash")) return 1;
            goto next;
        }

        strcmp_s("--no_hash", strnlen_s("--no_hash", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hash, &hash_status, ALG_DISABLE,
                               "--hash", "--no_hash")) return 1;
            goto next;
        }

        strcmp_s("--cmac", strnlen_s("--cmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->cmac, &cmac_status, ALG_ENABLE,
                               "--cmac", "--no_cmac")) return 1;
            goto next;
        }

        strcmp_s("--no_cmac", strnlen_s("--no_cmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->cmac, &cmac_status, ALG_DISABLE,
                               "--cmac", "--no_cmac")) return 1;
            goto next;
        }

        strcmp_s("--hmac", strnlen_s("--hmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hmac, &hmac_status, ALG_ENABLE,
                               "--hmac", "--no_hmac")) return 1;
            goto next;
        }

        strcmp_s("--no_hmac", strnlen_s("--no_hmac", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
            if (cli_alg_option(&cfg->hmac, &hmac_status, ALG_DISABLE,
                               "--hmac", "--no_hmac")) return 1;
            goto next;
        }

        strcmp_s("--kdf", strnlen_s("--kdf", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef OPENSSL_KDF_SUPPORT
            if (cli_alg_option(&cfg->kdf, &kdf_status, ALG_ENABLE,
                               "--kdf", "--no_kdf")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DOPENSSL_KDF_SUPPORT"
                   "\nThis option will have no effect.\n", "--kdf");
#endif
            goto next;
        }

        strcmp_s("--no_kdf", strnlen_s("--no_kdf", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef OPENSSL_KDF_SUPPORT
            if (cli_alg_option(&cfg->kdf, &kdf_status, ALG_DISABLE,
                               "--kdf", "--no_kdf")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DOPENSSL_KDF_SUPPORT"
                   "\nThis option will have no effect.\n", "--no_kdf");
#endif
            goto next;
        }

        strcmp_s("--dsa", strnlen_s("--dsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->dsa, &dsa_status, ALG_ENABLE,
                               "--dsa", "--no_dsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--dsa");
#endif
            goto next;
        }

        strcmp_s("--no_dsa", strnlen_s("--no_dsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->dsa, &dsa_status, ALG_DISABLE,
                               "--dsa", "--no_dsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_dsa");
#endif
            goto next;
        }

        strcmp_s("--rsa", strnlen_s("--rsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->rsa, &rsa_status, ALG_ENABLE,
                               "--rsa", "--no_rsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--rsa");
#endif
            goto next;
        }

        strcmp_s("--no_rsa", strnlen_s("--no_rsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->rsa, &rsa_status, ALG_DISABLE,
                               "--rsa", "--no_rsa")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_rsa");
#endif
            goto next;
        }

        strcmp_s("--drbg", strnlen_s("--drbg", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->drbg, &drbg_status, ALG_ENABLE,
                               "--drbg", "--no_drbg")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect\n", "--drbg");
#endif
            goto next;
        }

        strcmp_s("--no_drbg", strnlen_s("--no_drbg", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->drbg, &drbg_status, ALG_DISABLE,
                               "--drbg", "--no_drbg")) return 1;
#else
            printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nTHis option will have no effect.\n", "--no_drbg");
#endif
            goto next;
        }

        strcmp_s("--ecdsa", strnlen_s("--ecdsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->ecdsa, &ecdsa_status, ALG_ENABLE,
                               "--ecdsa", "--no_ecdsa")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--ecdsa");
#endif
            goto next;
        }

        strcmp_s("--no_ecdsa", strnlen_s("--no_ecdsa", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->ecdsa, &ecdsa_status, ALG_DISABLE,
                               "--ecdsa", "--no_ecdsa")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis options will have no effect.\n", "--no_ecdsa");
#endif
            goto next;
        }

        strcmp_s("--kas_ecc", strnlen_s("--kas_ecc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ecc, &kas_ecc_status, ALG_ENABLE,
                               "--kas_ecc", "--no_kas_ecc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--kas_ecc");
#endif
            goto next;
        }

        strcmp_s("--no_kas_ecc", strnlen_s("--no_kas_ecc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ecc, &kas_ecc_status, ALG_DISABLE,
                               "--kas_ecc", "--no_kas_ecc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_kas_ecc");
#endif
            goto next;
        }

        strcmp_s("--kas_ffc", strnlen_s("--kas_ffc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ffc, &kas_ffc_status, ALG_ENABLE,
                               "--kas_ffc", "--no_kas_ffc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--kas_ffc");
#endif
            goto next;
        }

        strcmp_s("--no_kas_ffc", strnlen_s("--no_kas_ffc", OPTION_STR_MAX), *argv, &diff);
        if (!diff) {
#ifdef ACVP_NO_RUNTIME
            if (cli_alg_option(&cfg->kas_ffc, &kas_ffc_status, ALG_DISABLE,
                               "--kas_ffc", "--no_kas_ffc")) return 1;
#else
            printf(ANSI_COLOR_YELLOW "Command warning... [%s]"ANSI_COLOR_RESET
                   "\nMissing compile flag -DACVP_NO_RUNTIME"
                   "\nThis option will have no effect.\n", "--no_kas_ffc");
#endif
            goto next;
        }

        /* If you get here, the command wasn't recognized */
        printf("Command error... Option not recognized: \"%s\"", *argv);
        print_usage(1);
        return 1;
next:
        argv++;
        argc--;
    }
    printf("\n");

    return 0;
}

