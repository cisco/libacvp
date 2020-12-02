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
#include "acvp/acvp.h"
#include "safe_lib.h"

#ifdef ACVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

static void print_usage(int code) {
    if (code == -1) {
        printf("\nInvalid usage...\n");
    } else {
        printf("\n===========================");
        printf("\n===== ACVP_APP USAGE ======");
        printf("\n===========================\n");
    }
    printf("To output version of library and of ACVP spec:\n");
    printf("      --version\n");
    printf("Logging level decides the amount of information output by the library. Logging level\n");
    printf("can be controlled using:\n");
    printf("      --none\n");
    printf("      --error\n");
    printf("      --warn\n");
    printf("      --status(default)\n");
    printf("      --info\n");
    printf("      --verbose\n");
    printf("\n");
    if (code >= ACVP_LOG_LVL_VERBOSE) {
        printf("-The warn logging level logs events that should be acted upon but do not halt\n");
        printf("the progress of the application running.\n");
        printf("-The default logging level provides basic information about the progress of the test\n");
        printf("session or the task being performed. This includes the possibility of logging large\n");
        printf("amounts of data IF the data is specifically requested.\n");
        printf("-The info logging level provides more information about the information being\n");
        printf("exchanged, including HTTP actions (get, put, etc). Data in/from these actions is\n");
        printf("logged but usually truncated.\n");
        printf("-The verbose logging level is substantially more detailed than even info level, and\n");
        printf("includes information about each vector set, test group,and even test case being\n");
        printf("processed. it also will automatically fetch the results of all test cases of a\n");
        printf("vector set in the event of it failing.\n");
        printf("\n");
        printf("For any activity requiring the creation of a test session and/or the processing\n");
        printf("of test cases, acvp_app requires the specification of at least one algorithm\n");
        printf("suite. Algorithm suites are enabled or disabled at build time depending on the\n");
        printf("capabilities of the provided cryptographic library.\n");
    }
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
#ifndef OPENSSL_NO_DSA
    printf("      --dsa\n");
    printf("      --kas_ffc\n");
#endif
    printf("      --rsa\n");
    printf("      --ecdsa\n");
    printf("      --drbg\n");
    printf("      --kas_ecc\n");
    printf("      --kas_ifc\n");
    printf("      --kts_ifc\n");
    printf("\n");

    if (code >= ACVP_LOG_LVL_VERBOSE) {
        printf("libacvp generates a file containing information that can be used for various tasks regarding\n");
        printf("a test session. By default, this is usually placed in the folder of the executable utilizing\n");
        printf("libacvp, though this can be different on some OS. The name, by default, is\n");
        printf("testSession_(ID number).json. The path and prefix can be controlled using ACV_SESSION_SAVE_PATH\n");
        printf("and ACV_SESSION_SAVE_PREFIX in your environment, respectively. Any tasks listed below that use\n");
        printf("<session_file> are in reference to this file.\n");
        printf("\n");
    }
    printf("Perform a FIPS Validation for this testSession:\n");
    printf("      --fips_validation <full metadata file>\n");
    printf("\n");
    printf("To specify a cert number associated with all prerequistes:\n");
    printf("      --certnum <string>\n");
    printf("\n");
    printf("To register manually using a JSON file instead of application settings use:\n");
    printf("      --manual_registration <file>\n");
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
    printf("Note: --resume_session and --get_results use the test session info file created automatically by the library as input\n");
    printf("\n");
    printf("To resume a previous test session that was interupted:\n");
    printf("      --resume_session <session_file>\n");
    printf("            Note: this does not save your arguments from your initial run and you MUST include them\n");
    printf("            again (e.x. --aes,  --vector_req and --fips_validation)\n");
    printf("\n");
    printf("To get the results of a previous test session:\n");
    printf("      --get_results <session_file>\n");
    printf("\n");
    printf("To GET status of request, such as validation or metadata:\n");
    printf("      --get <request string URL including ID>\n");
    printf("\n");
    printf("To POST metadata for vendor, person, etc.:\n");
    printf("      --post <metadata file>\n");
    printf("\n");
    printf("To PUT(modify)  metadata for vendor, person, etc. or PUT for validation:\n");
    printf("      --put <metadata file>\n");
    printf("\n");
    printf("If you are running a sample registration (querying for correct answers\n");
    printf("in addition to the normal registration flow) use:\n");
    printf("      --sample\n");
    printf("\n");
    printf("To get the expected results of a sample test session:\n");
    printf("      --get_expected_results <session_file>\n");
    printf("\n");
    printf("Some other options may support outputting to log OR saving to a file. To save to a file:\n");
    printf("      --save_to <file>\n");
    printf("\n");
    printf("In addition some options are passed to acvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to %s)\n", DEFAULT_URI_PREFIX);
    printf("    ACV_TOTP_SEED (when not set, client will not use Two-factor authentication)\n");
    printf("    ACV_CA_FILE\n");
    printf("    ACV_CERT_FILE\n");
    printf("    ACV_KEY_FILE\n");
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n\n");
    printf("Some options can be passed to the library itself with environment variables:\n\n");
    printf("    ACV_SESSION_SAVE_PATH (Location where test session info files are saved)\n");
    printf("    ACV_SESSION_SAVE_PREFIX (Determines file name of info file, followed by ID number\n");
    printf("    The following are used by the library for an HTTP user-agent string, only when\n");
    printf("    the information cannot be automatically collected:\n");
    printf("        ACV_OE_OSNAME\n");
    printf("        ACV_OE_OSVERSION\n");
    printf("        ACV_OE_ARCHITECTURE\n");
    printf("        ACV_OE_PROCESSOR\n");
    printf("        ACV_OE_COMPILER\n\n");

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
#ifndef OPENSSL_NO_DSA
    cfg->dsa = 1;
    cfg->kas_ffc = 1;
#endif
    cfg->rsa = 1;
    cfg->drbg = 1;
    cfg->ecdsa = 1;
    cfg->kas_ecc = 1;
    cfg->kas_ifc = 1;
    cfg->kts_ifc = 1;
#ifdef OPENSSL_KDF_SUPPORT
    cfg->kdf = 1;
#endif
}

int ingest_cli(APP_CONFIG *cfg, int argc, char **argv) {
    ketopt_t opt = KETOPT_INIT;
    int c = 0;

    cfg->empty_alg = 1;

    static ko_longopt_t longopts[] = {
        { "version", ko_no_argument, 301 },
        { "help", ko_optional_argument, 302 },
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
#ifndef OPENSSL_NO_DSA
        { "dsa", ko_no_argument, 316 },
        { "kas_ffc", ko_no_argument, 321 },
#endif
        { "rsa", ko_no_argument, 317 },
        { "drbg", ko_no_argument, 318 },
        { "ecdsa", ko_no_argument, 319 },
        { "kas_ecc", ko_no_argument, 320 },
        { "kas_ifc", ko_no_argument, 323 },
        { "kts_ifc", ko_no_argument, 324 },
        { "all_algs", ko_no_argument, 322 },
        { "manual_registration", ko_required_argument, 400 },
        { "kat", ko_required_argument, 401 },
        { "fips_validation", ko_required_argument, 402 },
        { "vector_req", ko_required_argument, 403 },
        { "vector_rsp", ko_required_argument, 404 },
        { "vector_upload", ko_required_argument, 405 },
        { "get", ko_required_argument, 406 },
        { "post", ko_required_argument, 407 },
        { "put", ko_required_argument, 408 },
        { "get_results", ko_required_argument, 409},
        { "certnum", ko_required_argument, 410 },
        { "resume_session", ko_required_argument, 411 },
        { "get_expected_results", ko_required_argument, 412 },
        { "save_to", ko_required_argument, 413},
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
            int diff = -1;
            strncmp_s(opt.arg, JSON_FILENAME_LENGTH + 1, "verbose", 7, &diff);
            if (!diff) {
                print_usage(ACVP_LOG_LVL_VERBOSE);
            } else { 
                print_usage(0);
            }
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
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 311) {
            cfg->tdes = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 312) {
            cfg->hash = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 313) {
            cfg->cmac = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 314) {
            cfg->hmac = 1;
            cfg->empty_alg = 0;
            continue;
        }
#ifdef OPENSSL_KDF_SUPPORT
        if (c == 315) {
            cfg->kdf = 1;
            cfg->empty_alg = 0;
            continue;
        }
#endif
#ifndef OPENSSL_NO_DSA
        if (c == 316) {
            cfg->dsa = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 321) {
            cfg->kas_ffc = 1;
            cfg->empty_alg = 0;
            continue;
        }
#endif
        if (c == 317) {
            cfg->rsa = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 318) {
            cfg->drbg = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 319) {
            cfg->ecdsa = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 320) {
            cfg->kas_ecc = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 322) {
            enable_all_algorithms(cfg);
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 323) {
            cfg->kas_ifc = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 324) {
            cfg->kts_ifc = 1;
            cfg->empty_alg = 0;
            continue;
        }
        if (c == 400) {
            int filename_len = 0;
            cfg->manual_reg = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--manual_registration", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->reg_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        if (c == 401) {
            int filename_len = 0;
            cfg->kat = 1;

            filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (filename_len > JSON_FILENAME_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--kat", opt.arg, JSON_FILENAME_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--fips_validation", opt.arg, JSON_FILENAME_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_req", opt.arg, JSON_FILENAME_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_rsp", opt.arg, JSON_FILENAME_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--vector_upload", opt.arg, JSON_FILENAME_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <string> \"%s\", is too long."
                       "\nMax allowed <string> length is (%d).\n",
                       "--get", opt.arg, JSON_REQUEST_LENGTH);
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
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--post", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->post_filename, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 408) {
            int put_filename_len = 0;
            cfg->put = 1;

            put_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (put_filename_len > JSON_REQUEST_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe <file> \"%s\", has a name that is too long."
                       "\nMax allowed <file> name length is (%d).\n",
                       "--put", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->put_filename, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 409) {
            int result_filename_len = 0;
            cfg->get_results = 1;

            result_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (result_filename_len > JSON_REQUEST_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                    "\nThe <file> \"%s\", has a name that is too long."
                    "\nMax allowed <file> name length is (%d).\n",
                    "--get_results", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->session_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }

        if (c == 410) {
            int certnum_len = 0;
            certnum_len = strnlen_s(opt.arg, JSON_STRING_LENGTH + 1);
            if (certnum_len > JSON_STRING_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                       "\nThe string used is too long."
                       "\nMax allowed string length is %d.\n",
                       "--certnum", JSON_STRING_LENGTH);
                return 1;
            }
            strcpy_s(value, JSON_STRING_LENGTH, opt.arg);
            continue;
        }
        if (c == 411) {
            int resume_filename_len = 0;
            cfg->resume_session = 1;

            resume_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (resume_filename_len > JSON_REQUEST_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                    "\nThe <file> \"%s\", has a name that is too long."
                    "\nMax allowed <file> name length is (%d).\n",
                    "--resume_session", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->session_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        if (c == 412) {
            int session_filename_len = 0;
            cfg->get_expected = 1;

            session_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (session_filename_len > JSON_REQUEST_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                    "\nThe <file> \"%s\", has a name that is too long."
                    "\nMax allowed <file> name length is (%d).\n",
                    "--get_expected_results", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }

            strcpy_s(cfg->session_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        if (c == 413) {
            int save_filename_len = 0;
            cfg->save_to = 1;

            save_filename_len = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
            if (save_filename_len > JSON_REQUEST_LENGTH) {
                print_usage(-1);
                printf(ANSI_COLOR_RED "Command error... [%s]"ANSI_COLOR_RESET
                    "\nThe <file> \"%s\", has a name that is too long."
                    "\nMax allowed <file> name length is (%d).\n",
                    "--save_to", opt.arg, JSON_FILENAME_LENGTH);
                return 1;
            }
            strcpy_s(cfg->save_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            continue;
        }
        
        if (c == '?') {
            print_usage(-1);
            printf(ANSI_COLOR_RED "unknown option: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - 1));
            return 1;
        }
        if (c == ':') {
            print_usage(-1);
            printf(ANSI_COLOR_RED "option missing arg: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - 1));
            return 1;
        }
    }

    if (cfg->save_to && !cfg->get_expected && !cfg->get) {
        printf("Warning: --save-to only works with --get and --get_expected. Option will be ignored.\n");
    }

    /* allopw put, post and get without algs defined */
    if (cfg->empty_alg && !cfg->post && !cfg->get && !cfg->put && !cfg->get_results
                   && !cfg->get_expected && !cfg->manual_reg && !cfg->vector_upload) {
        /* The user needs to select at least 1 algorithm */
        print_usage(-1);
        printf(ANSI_COLOR_RED "Requires at least 1 Algorithm Test Suite\n"ANSI_COLOR_RESET);
        return 1;
    }

    printf("\n");

    return 0;
}

