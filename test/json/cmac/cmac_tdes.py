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
    test_group = test_groups[3]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[3]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test

def gen(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "cmac_tdes.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "cmac_tdes.json"), "r") as f:
            j = json.load(f)

    # build a couple of full json files that use multiple testcases or testgroups
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]

    ##
    # The value for key:"tgId" is missing in the last test_group
    ##
    s = copy.deepcopy(single)
    tg = ref_last_testgroup(s)
    del tg["keyingOption"]

    with open(os.path.join(cur_dir, "cmac_tdes_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["mac"]

    with open(os.path.join(cur_dir, "cmac_tdes_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # Trim the testGroups to a single item and get a ref
    test_groups[1:] = []
    # Trim the tests to a single item and get a ref
    tests = test_groups[0]["tests"]
    tests[1:] = []

    ##
    # The key:"keyingOption" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["keyingOption"]
    with open(os.path.join(cur_dir, "cmac_tdes_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"keyingOption" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["keyingOption"] = 3
    with open(os.path.join(cur_dir, "cmac_tdes_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key1" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["key1"]
    with open(os.path.join(cur_dir, "cmac_tdes_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key2" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["key2"]
    with open(os.path.join(cur_dir, "cmac_tdes_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key3" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["key3"]
    with open(os.path.join(cur_dir, "cmac_tdes_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"msg" is too long
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["message"] = "a" * (131072 + 1) # ACVP_CMAC_MSG_MAX
    with open(os.path.join(cur_dir, "cmac_tdes_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The length of "key1" is wrong
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["key1"] = "a" * (64 + 1) # ACVP_CMAC_KEY_MAX
    with open(os.path.join(cur_dir, "cmac_tdes_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The length of "key2" is wrong
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["key2"] = "a" * (64 + 1) # ACVP_CMAC_KEY_MAX
    with open(os.path.join(cur_dir, "cmac_tdes_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The length of "key3" is wrong
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["key3"] = "a" * (64 + 1) # ACVP_CMAC_KEY_MAX
    with open(os.path.join(cur_dir, "cmac_tdes_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "cmac_tdes_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_cmac_tdes(file_in):
    """
    Main cmac_tdes entry point.
    :param file_in: Name (str) of the cmac_tdes JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    print(file_in)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen(j)
    else:
        gen()
