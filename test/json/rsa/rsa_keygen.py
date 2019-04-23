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


def gen(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "rsa_keygen.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "rsa_keygen.json"), "r") as f:
            j = json.load(f)

    # build a couple of full json files that use multiple testcases or testgroups
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]

    ##
    # The value for key:"tgId" is missing in the last test_group
    ##
    s = copy.deepcopy(single)
    tg = ref_last_testgroup(s)
    del tg["hashAlg"]

    with open(os.path.join(cur_dir, "rsa_keygen_24.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["seed"]

    with open(os.path.join(cur_dir, "rsa_keygen_25.json"), "w") as fp:
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
    with open(os.path.join(cur_dir, "rsa_keygen_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"mode" is missing.
    ##
    s = copy.deepcopy(single)
    del s[1]["mode"]
    with open(os.path.join(cur_dir, "rsa_keygen_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"mode" is wrong.
    ##
    s = copy.deepcopy(single)
    s[1]["mode"] = "my" + s[1]["mode"]
    with open(os.path.join(cur_dir, "rsa_keygen_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"infoGeneratedByServer" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["infoGeneratedByServer"]
    with open(os.path.join(cur_dir, "rsa_keygen_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"pubExp" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["pubExp"]
    with open(os.path.join(cur_dir, "rsa_keygen_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"pubExp" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["pubExp"] = "my" + tg["pubExp"]
    with open(os.path.join(cur_dir, "rsa_keygen_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"fixedPubExp" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["pubExp"] != "fixed":
        # Need to be "fixed" to kick of error condition
        tg["pubExp"] = "fixed"
    if "fixedPubExp" in tg:
        del tg["fixedPubExp"]
    with open(os.path.join(cur_dir, "rsa_keygen_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"keyFormat" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["keyFormat"]
    with open(os.path.join(cur_dir, "rsa_keygen_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"keyFormat" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["keyFormat"] = "my" + tg["keyFormat"]
    with open(os.path.join(cur_dir, "rsa_keygen_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"randPQ" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["randPQ"]
    with open(os.path.join(cur_dir, "rsa_keygen_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"randPQ" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["randPQ"] = "my" + tg["randPQ"]
    with open(os.path.join(cur_dir, "rsa_keygen_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"primeTest" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["randPQ"] not in ["B.3.3", "B.3.5", "B.3.6"]:
        # Need to be part of that set to kick of error condition
        tg["randPQ"] = "B.3.3"
    if "primeTest" in tg:
        del tg["primeTest"]
    with open(os.path.join(cur_dir, "rsa_keygen_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"primeTest" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["randPQ"] not in ["B.3.3", "B.3.5", "B.3.6"]:
        # Need to be part of that set to kick of error condition
        tg["randPQ"] = "B.3.3"

    if "primeTest" in tg:
        tg["primeTest"] = "my" + tg["primeTest"]
    else:
        tg["primeTest"] = "mytblC2"
    with open(os.path.join(cur_dir, "rsa_keygen_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"modulo" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["modulo"]
    with open(os.path.join(cur_dir, "rsa_keygen_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"modulo" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["modulo"] = 1024
    with open(os.path.join(cur_dir, "rsa_keygen_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"hashAlg" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["randPQ"] not in ["B.3.2", "B.3.4", "B.3.5"]:
        # Need to be part of that set to kick of error condition
        tg["randPQ"] = "B.3.2"

    if "hashAlg" in tg:
        del tg["hashAlg"]
    with open(os.path.join(cur_dir, "rsa_keygen_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"hashAlg" is wrong.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["randPQ"] not in ["B.3.2", "B.3.4", "B.3.5"]:
        # Need to be part of that set to kick of error condition
        tg["randPQ"] = "B.3.2"

    if "hashAlg" in tg:
        tg["hashAlg"] = "my" + tg["hashAlg"]
    else:
        tg["hashAlg"] = "mySHA-1"
    with open(os.path.join(cur_dir, "rsa_keygen_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"e" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["infoGeneratedByServer"] is False:
        # Need to enable to kick of error condition
        tg["infoGeneratedByServer"] = True
    if tg["pubExp"] != "random":
        # Need to be random
        tg["pubExp"] = "random"
    if "fixedPubExp" in tg:
        # Can't have the fixedPubExp
        del tg["fixedPubExp"]

    if "e" in t:
        del t["e"]
    with open(os.path.join(cur_dir, "rsa_keygen_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"e" string is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["infoGeneratedByServer"] is False:
        # Need to enable to kick of error condition
        tg["infoGeneratedByServer"] = True
    if tg["pubExp"] != "random":
        # Need to be random
        tg["pubExp"] = "random"
    if "fixedPubExp" in tg:
        # Can't have the fixedPubExp
        del tg["fixedPubExp"]

    t["e"] = "a" * 1025
    with open(os.path.join(cur_dir, "rsa_keygen_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"bitlens" list is wrong size.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["infoGeneratedByServer"] is False:
        # Need to enable to kick of error condition
        tg["infoGeneratedByServer"] = True

    t["bitlens"] = [0, 0, 0, 0, 0]
    with open(os.path.join(cur_dir, "rsa_keygen_20.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"seed" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["infoGeneratedByServer"] is False:
        # Need to enable to kick of error condition
        tg["infoGeneratedByServer"] = True

    if t["seed"]:
        del t["seed"]
    with open(os.path.join(cur_dir, "rsa_keygen_21.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"seed" string is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    if tg["infoGeneratedByServer"] is False:
        # Need to enable to kick of error condition
        tg["infoGeneratedByServer"] = True

    t["seed"] = "a" * 65
    with open(os.path.join(cur_dir, "rsa_keygen_22.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "rsa_keygen_23.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_rsa_keygen(file_in=None):
    """
    Main rsa_keygen entry point.
    :param file_in: Name (str) of the rsa_keygen JSON input file.
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
