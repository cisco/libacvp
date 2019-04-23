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
    printf("To process kat vectors from a JSON file use:\n");
    printf("      --kat <file>\n");
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

    if (empty_alg) {
        /* The user needs to select at least 1 algorithm */
        printf(ANSI_COLOR_RED "Requires at least 1 Algorithm Test Suite\n"ANSI_COLOR_RESET);
        print_usage(1);
        return 1;
    }

    printf("\n");

    return 0;
}

