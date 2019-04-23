#!/usr/bin/env python3
"""
* Copyright (c) 2019, Cisco Systems, Inc.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/cisco/libacvp/LICENSE
*
"""
import os
import logging
import argparse

from aes import main_aes
from des import main_des
from rsa import main_rsa_keygen
from cmac import main_cmac_aes
from cmac import main_cmac_tdes
from rsa import main_rsa_sigver
from rsa import main_rsa_siggen
from hash import main_hash
from ecdsa import main_ecdsa_kg
from ecdsa import main_ecdsa_kv
from ecdsa import main_ecdsa_sg
from ecdsa import main_ecdsa_sv
from kas_ecc import main_kas_ecc_comp
from kas_ecc import main_kas_ecc_cdh
from kas_ffc import main_kas_ffc_comp
from drbg import main_drbg



def get_full_path(filename, input_dir):
    if not filename:
        return None

    if input_dir is None:
        if not os.path.exists(filename):
            logger.error("File does not exist at %s. "
                         "Please specify full path to file, or use --input-dir.",
                         filename)
            return None
        return filename

    # Use input dir
    full_path = os.path.join(input_dir, filename)
    if not os.path.exists(full_path):
        logger.error("File does not exist at %s. "
                     "Please make sure the following is correct: --input-dir=%s",
                     full_path)
    return full_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate libacvp unit test JSON files. ' +
                    'Caution: existing output files will be overwritten.'
    )
    parser.add_argument('-l',
                        dest='log_level',
                        choices=['info', 'warning', 'error'],
                        help='Set the logging level.')
    parser.add_argument('--log-file',
                        action='store_true',
                        dest='log_file',
                        help='Log messages to a file instead of the console.')

    parser.add_argument('--aes',
                        action='store_true',
                        dest='aes',
                        help='Generate the "aes" test case files.')

    parser.add_argument('--aes_bf',
                        dest='aes_input',
                        help='Regen a new basefile for "aes" using this JSON input file.' +
                             ' Also generate all "aes" test case files.')

    parser.add_argument('--des',
                        action='store_true',
                        dest='des',
                        help='Generate the "des" test case files.')
    parser.add_argument('--des_bf',
                        dest='des_input',
                        help='Regen a new basefile for "des" using this JSON input file.' +
                             ' Also generate all "des" test case files.')

    parser.add_argument('--drbg',
                        action='store_true',
                        dest='drbg',
                        help='Generate the "drbg" test case files.')
    parser.add_argument('--drbg_bf',
                        dest='drbg_input',
                        help='Regen a new basefile for "drbg" using this JSON input file.' +
                             ' Also generate all "drbg" test case files.')

    parser.add_argument('--rsa-keygen',
                        action='store_true',
                        dest='rsa_keygen',
                        help='Generate the "rsa-keygen" test case files.')
    parser.add_argument('--rsa-keygen_bf',
                        dest='rsa_keygen_input',
                        help='Regen a new basefile for "rsa-keygen" using this JSON input file.' +
                             ' Also generate all "rsa-keygen" test case files.')

    parser.add_argument('--cmac-aes',
                        action='store_true',
                        dest='cmac_aes',
                        help='Generate the "cmac-aes" test case files.')
    parser.add_argument('--cmac-aes_bf',
                        dest='cmac_aes_input',
                        help='Regen a new basefile for "cmac-aes" using this JSON input file.' +
                             ' Also generate all "cmac-aes" test case files.')

    parser.add_argument('--cmac-tdes',
                        action='store_true',
                        dest='cmac_tdes',
                        help='Generate the "cmac-tdes" test case files.')
    parser.add_argument('--cmac-tdes_bf',
                        dest='cmac_tdes_input',
                        help='Regen a new basefile for "cmac-tdes" using this JSON input file.' +
                             ' Also generate all "cmac-tdes" test case files.')

    parser.add_argument('--kas-ecc-cdh',
                        action='store_true',
                        dest='kas_ecc_cdh',
                        help='Generate the "kas-ecc-cdh" test case files.')
    parser.add_argument('--kas-ecc-cdh_bf',
                        dest='kas_ecc_cdh_input',
                        help='Regen a new basefile for "kas-ecc-cdh" using this JSON input file.' +
                             ' Also generate all "kas-ecc-cdh" test case files.')

    parser.add_argument('--kas-ecc-comp',
                        action='store_true',
                        dest='kas_ecc_comp',
                        help='Generate the "kas-ecc-comp" test case files.')
    parser.add_argument('--kas-ecc-comp_bf',
                        dest='kas_ecc_comp_input',
                        help='Regen a new basefile for "kas-ecc-comp" using this JSON input file.' +
                             ' Also generate all "kas-ecc-comp" test case files.')

    parser.add_argument('--kas-ffc-comp',
                        action='store_true',
                        dest='kas_ffc_comp',
                        help='Generate the "kas-ffc-comp" test case files.')
    parser.add_argument('--kas-ffc-comp_bf',
                        dest='kas_ffc_comp_input',
                        help='Regen a new basefile for "kas-ffc-comp" using this JSON input file.' +
                             ' Also generate all "kas-ffc-comp" test case files.')

    parser.add_argument('--rsa-siggen',
                        action='store_true',
                        dest='rsa_siggen',
                        help='Generate the "rsa-siggen" test case files.')
    parser.add_argument('--rsa-siggen_bf',
                        dest='rsa_siggen_input',
                        help='Regen a new basefile for "rsa-siggen" using this JSON input file.' +
                             ' Also generate all "rsa-siggen" test case files.')

    parser.add_argument('--rsa-sigver',
                        action='store_true',
                        dest='rsa_sigver',
                        help='Generate the "rsa-sigver" test case files.')
    parser.add_argument('--rsa-sigver_bf',
                        dest='rsa_sigver_input',
                        help='Regen a new basefile for "rsa-sigver" using this JSON input file.' +
                             ' Also generate all "rsa-sigver" test case files.')

    parser.add_argument('--hash',
                        action='store_true',
                        dest='hash',
                        help='Generate the "hash" test case files.')
    parser.add_argument('--hash_bf',
                        dest='hash_input',
                        help='Regen a new basefile for "hash" using this JSON input file.' +
                             ' Also generate all "hash" test case files.')

    parser.add_argument('--ecdsa-kg',
                        action='store_true',
                        dest='ecdsa_kg',
                        help='Generate the "ecdsa-keygen" test case files.')
    parser.add_argument('--ecdsa-kg_bf',
                        dest='ecdsa_kg_input',
                        help='Regen a new basefile for "ecdsa-keygen" using this JSON input file.' +
                             ' Also generate all "ecdsa-keygen" test case files.')

    parser.add_argument('--ecdsa-kv',
                        action='store_true',
                        dest='ecdsa_kv',
                        help='Generate the "ecdsa-keyver" test case files.')
    parser.add_argument('--ecdsa-kv_bf',
                        dest='ecdsa_kv_input',
                        help='Regen a new basefile for "ecdsa-keyver" using this JSON input file.' +
                             ' Also generate all "ecdsa-keyver" test case files.')

    parser.add_argument('--ecdsa-sg',
                        action='store_true',
                        dest='ecdsa_sg',
                        help='Generate the "ecdsa-siggen" test case files.')
    parser.add_argument('--ecdsa-sg_bf',
                        dest='ecdsa_sg_input',
                        help='Regen a new basefile for "ecdsa-siggen" using this JSON input file.' +
                             ' Also generate all "ecdsa-siggen" test case files.')

    parser.add_argument('--ecdsa-sv',
                        action='store_true',
                        dest='ecdsa_sv',
                        help='Generate the "ecdsa-sigver" test case files.')
    parser.add_argument('--ecdsa-sv_bf',
                        dest='ecdsa_sv_input',
                        help='Regen a new basefile for "ecdsa-sigver" using this JSON input file.' +
                             ' Also generate all "ecdsa-sigver" test case files.')

    parser.add_argument('--input-dir',
                        dest='input_dir',
                        help='The absolute path to directory where JSON input files currently exist')
    args = parser.parse_args()

    ##
    # Configure logging
    ##
    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

    log_level = None
    if args.log_level:
        log_level = LEVELS[args.log_level.lower()]

    log_file = None
    if args.log_file:
        logging.basicConfig(
            filename="generate_json.log",
            level=log_level,
            format="%(levelname)s - %(asctime)s - {%(name)s:%(lineno)d} --> %(message)s",
        )
    else:
        logging.basicConfig(
            level=log_level,
            format="%(levelname)s - {%(name)s:%(lineno)d} --> %(message)s",
        )

    logger = logging.getLogger(__name__)

    print("generate_json.py running...\n")

    if args.aes or args.aes_input:
        file_in = None
        if args.aes_input:
            file_in = get_full_path(args.aes_input, args.input_dir)
        main_aes(file_in)

    if args.des or args.des_input:
        file_in = None
        if args.des_input:
            file_in = get_full_path(args.des_input, args.input_dir)
        main_des(file_in)

    if args.drbg or args.drbg_input:
        file_in = None
        if args.drbg_input:
            file_in = get_full_path(args.drbg_input, args.input_dir)
        main_drbg(file_in)

    if args.rsa_keygen or args.rsa_keygen_input:
        file_in = None
        if args.rsa_keygen_input:
            file_in = get_full_path(args.rsa_keygen_input, args.input_dir)
        main_rsa_keygen(file_in)

    if args.cmac_aes or args.cmac_aes_input:
        file_in = None
        if args.cmac_aes_input:
            file_in = get_full_path(args.cmac_aes_input, args.input_dir)
        main_cmac_aes(file_in)

    if args.cmac_tdes or args.cmac_tdes_input:
        file_in = None
        if args.cmac_tdes_input:
            file_in = get_full_path(args.cmac_tdes_input, args.input_dir)
        main_cmac_tdes(file_in)

    if args.kas_ecc_comp or args.kas_ecc_comp_input:
        file_in = None
        if args.kas_ecc_comp_input:
            file_in = get_full_path(args.kas_ecc_comp_input, args.input_dir)
        main_kas_ecc_comp(file_in)

    if args.kas_ecc_cdh or args.kas_ecc_cdh_input:
        file_in = None
        if args.kas_ecc_cdh_input:
            file_in = get_full_path(args.kas_ecc_cdh_input, args.input_dir)
        main_kas_ecc_cdh(file_in)

    if args.kas_ffc_comp or args.kas_ffc_comp_input:
        file_in = None
        if args.kas_ffc_comp_input:
            file_in = get_full_path(args.kas_ffc_comp_input, args.input_dir)
        main_kas_ffc_comp(file_in)

    if args.rsa_siggen or args.rsa_siggen_input:
        file_in = None
        if args.rsa_siggen_input:
            file_in = get_full_path(args.rsa_siggen_input, args.input_dir)
        main_rsa_siggen(file_in)

    if args.rsa_sigver or args.rsa_sigver_input:
        file_in = None
        if args.rsa_sigver_input:
            file_in = get_full_path(args.rsa_sigver_input, args.input_dir)
        main_rsa_sigver(file_in)

    if args.hash or args.hash_input:
        file_in = None
        if args.hash_input:
            file_in = get_full_path(args.hash_input, args.input_dir)
        main_hash(file_in)

    if args.ecdsa_kg or args.ecdsa_kg_input:
        file_in = None
        if args.ecdsa_kg_input:
            file_in = get_full_path(args.ecdsa_kg_input, args.input_dir)
        main_ecdsa_kg(file_in)

    if args.ecdsa_kv or args.ecdsa_kv_input:
        file_in = None
        if args.ecdsa_kv_input:
            file_in = get_full_path(args.ecdsa_kv_input, args.input_dir)
        main_ecdsa_kv(file_in)

    if args.ecdsa_sg or args.ecdsa_sg_input:
        file_in = None
        if args.ecdsa_sg_input:
            file_in = get_full_path(args.ecdsa_sg_input, args.input_dir)
        main_ecdsa_sg(file_in)

    if args.ecdsa_sv or args.ecdsa_sv_input:
        file_in = None
        if args.ecdsa_sv_input:
            file_in = get_full_path(args.ecdsa_sv_input, args.input_dir)
        main_ecdsa_sv(file_in)


    logger.warning("SUCCESS")
    exit(0)
