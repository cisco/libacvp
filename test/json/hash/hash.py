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
    test_group = test_groups[0]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[128]

    return test


def gen(j=None):
    if j:
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "hash.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "hash.json"), "r") as f:
            j = json.load(f)

    # build a couple of full json files that use multiple testcases or testgroups
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]

    ##
    # The value for key:"tgId" is missing in the last test_group
    ##
    s = copy.deepcopy(single)
    tg = ref_last_testgroup(s)
    del tg["testType"]

    with open(os.path.join(cur_dir, "hash_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["msg"]

    with open(os.path.join(cur_dir, "hash_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # Trim the testGroups to a single item and get a ref
    test_groups[1:] = []
    # Trim the tests to a single item and get a ref
    tests = test_groups[0]["tests"]
    tests[1:] = []

    ##
    # The value for key:"algorithm" is wrong.
    ##
    s = copy.deepcopy(single)
    s[1]["algorithm"] = "my" + s[1]["algorithm"]
    with open(os.path.join(cur_dir, "hash_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"testType" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["testType"]
    with open(os.path.join(cur_dir, "hash_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"testType" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["testType"] = "my" + tg["testType"]
    with open(os.path.join(cur_dir, "hash_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"msg" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["msg"]
    with open(os.path.join(cur_dir, "hash_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"msg" string is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)

    t["msg"] = "a" * 35001 # ACVP_HASH_MSG_STR_MAX
    with open(os.path.join(cur_dir, "hash_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)

    del tg["tgId"]
    with open(os.path.join(cur_dir, "hash_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_hash(file_in=None):
    """
    Main hash entry point.
    :param file_in: Name (str) of the hash JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen(j)
    else:
        gen()
