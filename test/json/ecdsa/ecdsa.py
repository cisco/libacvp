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


def gen_kg(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "ecdsa_keygen.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "ecdsa_keygen.json"), "r") as f:
            j = json.load(f)

    # Trim the testGroups to a single item and get a ref
    kg_single = copy.copy(j)

    ##
    # The value for key:"algorithm" is wrong.
    ##
    s = copy.deepcopy(kg_single)
    s[1]["algorithm"] = "my" + s[1]["algorithm"]
    with open(os.path.join(cur_dir, "ecdsa_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"mode" is missing.
    ##
    s = copy.deepcopy(kg_single)
    del s[1]["mode"]
    with open(os.path.join(cur_dir, "ecdsa_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"mode" is wrong.
    ##
    s = copy.deepcopy(kg_single)
    s[1]["mode"] = "my" + s[1]["mode"]
    with open(os.path.join(cur_dir, "ecdsa_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"testGroups" is missing.
    ##
    s = copy.deepcopy(kg_single)
    del s[1]["testGroups"]
    with open(os.path.join(cur_dir, "ecdsa_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"curve" is missing.
    ##
    s = copy.deepcopy(kg_single)
    tg, t = ref_testgroup_and_test(s)
    del tg["curve"]
    with open(os.path.join(cur_dir, "ecdsa_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"curve" string is wrong.
    ##
    s = copy.deepcopy(kg_single)
    tg, t = ref_testgroup_and_test(s)
    tg["curve"] = "my" + tg["curve"]
    with open(os.path.join(cur_dir, "ecdsa_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(kg_single)
    tg, t = ref_testgroup_and_test(s)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "ecdsa_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def gen_kv(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "ecdsa_keyver.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "ecdsa_keyver.json"), "r") as f:
            j = json.load(f)

    # Trim the testGroups to a single item and get a ref
    kv_single = copy.copy(j)

    ##
    # The key:"qx" string is missing.
    ##
    s = copy.deepcopy(kv_single)
    tg, t = ref_testgroup_and_test(s)
    del t["qx"]
    with open(os.path.join(cur_dir, "ecdsa_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"qx" string is too long.
    ##
    s = copy.deepcopy(kv_single)
    tg, t = ref_testgroup_and_test(s)
    t["qy"] = "a" * 513
    with open(os.path.join(cur_dir, "ecdsa_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def gen_sg(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "ecdsa_siggen.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "ecdsa_siggen.json"), "r") as f:
            j = json.load(f)

    # Trim the testGroups to a single item and get a ref
    sg_single = copy.copy(j)

    ##
    # The value for key:"hashAlg" string is wrong.
    ##
    s = copy.deepcopy(sg_single)
    tg, t = ref_testgroup_and_test(s)
    tg["hashAlg"] = "my" + tg["hashAlg"]
    with open(os.path.join(cur_dir, "ecdsa_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"message" string is missing.
    ##
    s = copy.deepcopy(sg_single)
    tg, t = ref_testgroup_and_test(s)
    del t["message"]
    with open(os.path.join(cur_dir, "ecdsa_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def gen_sv(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "ecdsa_sigver.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "ecdsa_sigver.json"), "r") as f:
            j = json.load(f)

    # Trim the testGroups to a single item and get a ref
    sv_single = copy.copy(j)

    ##
    # The key:"hashAlg" is missing.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    del tg["hashAlg"]
    with open(os.path.join(cur_dir, "ecdsa_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"message" string is too long.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    t["message"] = "a" * 8193
    with open(os.path.join(cur_dir, "ecdsa_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"qy" string is missing.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    del t["qy"]
    with open(os.path.join(cur_dir, "ecdsa_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"qx" string is too long.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    t["qx"] = "a" * 513
    with open(os.path.join(cur_dir, "ecdsa_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"r" string is missing.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    del t["r"]
    with open(os.path.join(cur_dir, "ecdsa_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"s" string is missing.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    del t["s"]
    with open(os.path.join(cur_dir, "ecdsa_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"r" string is too long.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    t["r"] = "a" * 513
    with open(os.path.join(cur_dir, "ecdsa_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"qx" string is too long.
    ##
    s = copy.deepcopy(sv_single)
    tg, t = ref_testgroup_and_test(s)
    t["s"] = "a" * 513
    with open(os.path.join(cur_dir, "ecdsa_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_ecdsa_kg(file_in=None):
    """
    Main ecdsa entry point.
    :param file_in: Name (str) of the ecdsa JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen_kg(j)
    else:
        gen_kg()


def main_ecdsa_kv(file_in=None):
    """
    Main ecdsa entry point.
    :param file_in: Name (str) of the ecdsa JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen_kv(j)
    else:
        gen_kv()


def main_ecdsa_sg(file_in=None):
    """
    Main ecdsa entry point.
    :param file_in: Name (str) of the ecdsa JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen_sg(j)
    else:
        gen_sg()


def main_ecdsa_sv(file_in=None):
    """
    Main ecdsa entry point.
    :param file_in: Name (str) of the ecdsa JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen_sv(j)
    else:
        gen_sv()

