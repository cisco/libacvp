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
import json
import copy


cur_dir = os.path.dirname(__file__)


def ref_testgroup_and_test(single):
    # Get ref to single testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[0]

    # Get ref to single test item
    tests = test_group["tests"]
    test = tests[0]

    return test_group, test

def ref_last_testgroup(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[1]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[1]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test


def gen_siggen(j):
    # This is a clean file. All of the JSON should be correct.
    with open(os.path.join(cur_dir, "rsa_siggen.json"), "w") as fp:
        json.dump(j, fp, indent=2)

    # build a couple of full json files that use multiple testcases or testgroups
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]

    ##
    # The value for key:"tgId" is missing in the last test_group
    ##
    s = copy.deepcopy(single)
    tg = ref_last_testgroup(s)
    del tg["hashAlg"]

    with open(os.path.join(cur_dir, "rsa_siggen_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["message"]

    with open(os.path.join(cur_dir, "rsa_siggen_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # Trim the testGroups to a single item and get a ref
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]
    test_groups[1:] = []
    # Trim the tests to a single item and get a ref
    tests = test_groups[0]["tests"]
    tests[1:] = []

    ##
    # The value for key:"algorithm" is wrong.
    ##
    s = copy.deepcopy(single)
    s[1]["algorithm"] = "my" + s[1]["algorithm"]
    with open(os.path.join(cur_dir, "rsa_siggen_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"mode" is missing.
    ##
    s = copy.deepcopy(single)
    del s[1]["mode"]
    with open(os.path.join(cur_dir, "rsa_siggen_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"mode" is wrong.
    ##
    s = copy.deepcopy(single)
    s[1]["mode"] = "my" + s[1]["mode"]
    with open(os.path.join(cur_dir, "rsa_siggen_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"sigType" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["sigType"]
    with open(os.path.join(cur_dir, "rsa_siggen_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"hashAlg" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["hashAlg"]
    with open(os.path.join(cur_dir, "rsa_siggen_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"modulo" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["hashAlg"]
    with open(os.path.join(cur_dir, "rsa_siggen_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"modulo" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["modulo"] = -999
    with open(os.path.join(cur_dir, "rsa_siggen_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"message" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["message"]
    with open(os.path.join(cur_dir, "rsa_siggen_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"tcId" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["tcId"]
    with open(os.path.join(cur_dir, "rsa_siggen_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"message" is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["message"] = "a" * (1024 + 1) # ACVP_RSA_MSGLEN_MAX
    with open(os.path.join(cur_dir, "rsa_siggen_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    return 0


def main_rsa_siggen(file_in):
    """
    Main rsa_sig entry point.
    :param file_in: Name (str) of the rsa_sig JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    print(file_in)

    try:
        with open(file_in, "r") as f:
            try:
                # Load the JSON into j object (should be a list)
                j = json.load(f)
                if gen_siggen(j):
                    return 1
            except json.JSONDecodeError:
                logger.error("JSONDecodeError for file_in=%s", file_in)
                return 1
    except IOError:
        logger.error("IOError for file_in=%s", file_in)
        return 1


    return 0
