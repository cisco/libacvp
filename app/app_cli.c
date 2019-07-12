/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <stdio.h>
#include "ketopt.h"
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
    printf("Perform a FIPS Validation for this testSession:\n");
    printf("      --fips_validation\n");
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
    printf("      --all_algs (Enable all of the suites below)\n");
    printf("      --aes\n");
    printf("      --tdes\n");
    printf("      --hash\n");
    printf("      --cmac\n");
    printf("      --hmac\n");
#ifdef OPENSSL_KDF_SUPPORT
    printf("      --kdf\n");
#endif
#ifdef ACVP_NO_RUNTIME
    printf("      --dsa\n");
    printf("      --rsa\n");
    printf("      --ecdsa\n");
    printf("      --drbg\n");
    printf("      --kas_ecc\n");
    printf("      --kas_ffc\n");
#endif
    printf("\n");
    printf("To register a formatted JSON file use:\n");
    printf("      --json <file>\n");
    printf("\n");
    printf("To register and save the vectors to file:\n");
    printf("      --vector_req <file>\n");
    printf("\n");
    printf("To process saved vectors and write results/responses to file:\n");
    printf("      --vector_req <file>\n");
    printf("      --vector_rsp <file>\n");
    printf("\n");
    printf("To upload vector responses from file:\n");
    printf("      --vector_upload <file>\n");
    printf("\n");
    printf("To process kat vectors from a JSON file use:\n");
    printf("      --kat <file>\n");
    printf("\n");
    printf("To GET status of request, such as validation or metadata:\n");
    printf("      --get <request string URL including ID>\n");
    printf("\n");
    printf("\n");
    printf("To POST metadata for vendor, person, etc.:\n");
    printf("      --post <metadata file>\n");
    printf("\n");
    printf("If you are running a sample registration (querying for correct answers\n");
    printf("in addition to the normal registration flow) use:\n");
    printf("      --sample\n");
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

static void default_config(APP_CONFIG *cfg) {
    cfg->level = ACVP_LOG_LVL_STATUS;
}

static void enable_all_algorithms(APP_CONFIG *cfg) {
    cfg->aes = 1;
    cfg->tdes = 1;
    cfg->hash = 1;
    cfg->cmac = 1;
    cfg->hmac = 1;
    /* These require the fom */
#ifdef ACVP_NO_RUNTIME
    cfg->dsa = 1;
    cfg->rsa = 1;
    cfg->drbg = 1;
    cfg->ecdsa = 1;
    cfg->kas_ecc = 1;
    cfg->kas_ffc = 1;
#endif
#ifdef OPENSSL_KDF_SUPPORT
    cfg->kdf = 1;
#endif
}

int ingest_cli(APP_CONFIG *cfg, int argc, char **argv) {
    ketopt_t opt = KETOPT_INIT;
    int c = 0;
    int empty_alg = 1;

    static ko_longopt_t longopts[] = {
        { "version", ko_no_argument, 301 },
        { "help", ko_no_argument, 302 },
        { "info", ko_no_argument, 303 },
        { "status", ko_no_argument, 304 },
        { "warn", ko_no_argument, 305 },
        { "error", ko_no_argument, 306 },
        { "verbose", ko_no_argument, 307 },
        { "none", ko_no_argument, 308 },
        { "sample", ko_no_argument, 309 },
        { "aes", ko_no_argument, 310 },
        { "tdes", ko_no_argument, 311 },
        { "hash", ko_no_argument, 312 },
        { "cmac", ko_no_argument, 313 },
        { "hmac", ko_no_argument, 314 },
#ifdef OPENSSL_KDF_SUPPORT
        { "kdf", ko_no_argument, 315 },
#endif
#ifdef ACVP_NO_RUNTIME
        { "dsa", ko_no_argument, 316 },
        { "rsa", ko_no_argument, 317 },
        { "drbg", ko_no_argument, 318 },
        { "ecdsa", ko_no_argument, 319 },
        { "kas_ecc", ko_no_argument, 320 },
        { "kas_ffc", ko_no_argument, 321 },
#endif
        { "all_algs", ko_no_argument, 322 },
        { "json", ko_required_argument, 400 },
        { "kat", ko_required_argument, 401 },
        { "fips_validation", ko_required_argument, 402 },
        { "vector_req", ko_required_argument, 403 },
        { "vector_rsp", ko_required_argument, 404 },
        { "vector_upload", ko_required_argument, 405 },
        { "get", ko_required_argument, 406 },
        { "post", ko_required_argument, 407 },
        { NULL, 0, 0 }
    };

    /* Set the default configuration values */
    default_config(cfg);

    while ((c = ketopt(&opt, argc, argv, 1, "vh", longopts)) >= 0) {
        if (c == 'v') {
            printf("\nACVP library version(protocol version): %s(%s)\n", acvp_version(), acvp_protocol_version());
            return 1;
        }
        if (c == 'h') {
            print_usage(0);
            return 1;
        }
        if (c == 301) {
            printf("\nACVP library version(protocol version): %s(%s)\n", acvp_version(), acvp_protocol_version());
            return 1;
        }
        if (c == 302) {
            print_usage(0);
            return 1;
        }
        if (c == 303) {
            cfg->level = ACVP_LOG_LVL_INFO;
            continue;
        }
        if (c == 304) {
            cfg->level = ACVP_LOG_LVL_STATUS;
            continue;
        }
        if (c == 305) {
            cfg->level = ACVP_LOG_LVL_WARN;
            continue;
        }
        if (c == 306) {
            cfg->level = ACVP_LOG_LVL_ERR;
            continue;
        }
        if (c == 307) {
            cfg->level = ACVP_LOG_LVL_VERBOSE;
            continue;
        }
        if (c == 308) {
            cfg->level = ACVP_LOG_LVL_NONE;
            continue;
        }
        if (c == 309) {
            cfg->sample = 1;
            continue;
        }
        if (c == 310) {
            cfg->aes = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 311) {
            cfg->tdes = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 312) {
            cfg->hash = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 313) {
            cfg->cmac = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 314) {
            cfg->hmac = 1;
            empty_alg = 0;
            continue;
        }
#ifdef OPENSSL_KDF_SUPPORT
        if (c == 315) {
            cfg->kdf = 1;
            empty_alg = 0;
            continue;
        }
#endif
#ifdef ACVP_NO_RUNTIME
        if (c == 316) {
            cfg->dsa = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 317) {
            cfg->rsa = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 318) {
            cfg->drbg = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 319) {
            cfg->ecdsa = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 320) {
            cfg->kas_ecc = 1;
            empty_alg = 0;
            continue;
        }
        if (c == 321) {
            cfg->kas_ffc = 1;
            empty_alg = 0;
            continue;
        }
#endif
        if (c == 322) {
            enable_all_algorithms(cfg);
            empty_alg = 0;
            continue;
        }
        if (c == 400) {
            int filename_len = 0;
            cfg->json = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--json", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->json_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        if (c == 401) {
            int filename_len = 0;
            cfg->kat = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--kat", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->kat_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        if (c == 402) {
            int filename_len = 0;
            cfg->fips_validation = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--fips_validation", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->validation_metadata_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 403) {
            int filename_len = 0;
            cfg->vector_req = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_req", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->vector_req_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 404) {
            int rsp_filename_len = 0;
            cfg->vector_rsp = 1;

            rsp_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (rsp_filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_rsp", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->vector_rsp_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 405) {
            int upload_filename_len = 0;
            cfg->vector_upload = 1;

            upload_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (upload_filename_len > JSON_FILENAME_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_upload", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->vector_upload_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 406) {
            int get_string_len = 0;
            cfg->get = 1;

            get_string_len = strnlen_s(opt.arg, JSON_REQUEST_LENGTH + 1);
            if (get_string_len > JSON_REQUEST_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <string> \"%s\", is too long."
                       "\nMax allowed <string> length is (%d).\n",
                       "--get", opt.arg, JSON_REQUEST_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->get_string, JSON_REQUEST_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 407) {
            int post_filename_len = 0;
            cfg->post = 1;

            post_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (post_filename_len > JSON_REQUEST_LENGTH) {
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--post", opt.arg, JSON_FILENAME_LENGTH);
                print_usage(1);
                return 1;
            }

            strcpy_s(cfg->post_filename, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == '?') {
            printf(ANSI_COLOR_RED "unknown option: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - 1));
            print_usage(1);
            return 1;
        }
        if (c == ':') {
            printf(ANSI_COLOR_RED "option missing arg: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - 1));
            print_usage(1);
            return 1;
        }
    }

    /* allopw post and get without algs defined */
    if (empty_alg && !cfg->post && !cfg->get) {
        /* The user needs to select at least 1 algorithm */
        printf(ANSI_COLOR_RED "Requires at least 1 Algorithm Test Suite\n"ANSI_COLOR_RESET);
        print_usage(1);
        return 1;
    }

    printf("\n");

    return 0;
}

