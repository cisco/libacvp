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


class Trim:
    def __init__(self):
        self.got_it = False

    def keep(self, obj):
        """
        Take a testGroup dict, and decide whether to keep or remove.
        We only want the VAL because it includes more fields.
        :param obj: testGroup dict
        :return: True to keep
        :return: False to remove
        """
        if self.got_it:
            return False
        else:
            # Trim the tests down to 1 item
            obj["tests"] = obj["tests"][:1]
            self.got_it = True
            return True

    def run(self, j_list):
        # Start from index 1 to avoid the version object
        test_groups = j_list[1]["testGroups"]

        tmp = [x for x in test_groups if self.keep(x)]
        j_list[1]["testGroups"] = tmp


def ref_testgroup_and_test(j_list):
    # Start from index 1 to avoid the version object
    test_group = j_list[1]["testGroups"][0]

    # Get ref to single test item
    tests = test_group["tests"]
    test = tests[0]

    return test_group, test


def convert_to_ctr(s):
    if s[1]["algorithm"] == "ctrDRBG":
        # Already counter
        return

    s[1]["algorithm"] = "ctrDRBG"

    tg, t = ref_testgroup_and_test(s)
    tg["mode"] = "AES-128"
    tg["derFunc"] = True
    tg["entropyInputLen"] = 128
    tg["reSeed"] = False
    tg["nonceLen"] = 64
    tg["persoStringLen"] = 0
    tg["additionalInputLen"] = 0
    tg["returnedBitsLen"] = 256

    t["entropyInput"] = "72EBE6DA2EF6E30519572A2D0BF024CC"
    t["nonce"] = "BA7C736B3D409457"
    t["persoString"] = ""

    otherInput = t["otherInput"]
    otherInput[0]["intendedUse"] = "generate"
    otherInput[0]["additionalInput"] = ""
    otherInput[0]["entropyInput"] = "F72B6D7CC4925C38D46CF66D20D5EFDF"
    otherInput[1]["intendedUse"] = "generate"
    otherInput[1]["additionalInput"] = ""
    otherInput[1]["entropyInput"] = "5935987415D3EAC153A4458B1B719C37"

def ref_last_testgroup(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[53]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[53]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test

def gen(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "drbg.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "drbg.json"), "r") as f:
            j = json.load(f)

    # build a couple of full json files that use multiple testcases or testgroups
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]

    ##
    # The value for key:"tgId" is missing in the last test_group
    ##
    s = copy.deepcopy(single)
    tg = ref_last_testgroup(s)
    del tg["mode"]

    with open(os.path.join(cur_dir, "drbg_33.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["nonce"]

    with open(os.path.join(cur_dir, "drbg_34.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # Trim the list!
    ##
    trim = Trim()
    trim.run(j)

    # Ensure that it is counter, because more code paths in libacvp kat handler.
    convert_to_ctr(j)

    # The key:"algorithm" is missing.
    s = copy.deepcopy(j)
    del s[1]["algorithm"]
    with open(os.path.join(cur_dir, "drbg_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"algorithm" is wrong.
    s = copy.deepcopy(j)
    s[1]["algorithm"] = "my" + s[1]["algorithm"]
    with open(os.path.join(cur_dir, "drbg_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"mode" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["mode"]
    with open(os.path.join(cur_dir, "drbg_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"mode" is wrong.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["mode"] = "my" + tg["mode"]
    with open(os.path.join(cur_dir, "drbg_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"predResistance" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["predResistance"]
    with open(os.path.join(cur_dir, "drbg_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"derFunc" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["derFunc"]
    with open(os.path.join(cur_dir, "drbg_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInputLen" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["entropyInputLen"]
    with open(os.path.join(cur_dir, "drbg_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"entropyInputLen" is too small.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["entropyInputLen"] = 80 - 1
    with open(os.path.join(cur_dir, "drbg_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"entropyInputLen" is too big.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["entropyInputLen"] = 1048576 + 1
    with open(os.path.join(cur_dir, "drbg_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"nonceLen" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["nonceLen"]
    with open(os.path.join(cur_dir, "drbg_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"nonceLen" is too small.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["nonceLen"] = 40 - 1
    with open(os.path.join(cur_dir, "drbg_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"nonceLen" is too big.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["nonceLen"] = 512 + 1
    with open(os.path.join(cur_dir, "drbg_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"persoStringLen" is too big.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["persoStringLen"] = 1048576 + 1
    with open(os.path.join(cur_dir, "drbg_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"returnedBitsLen" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["returnedBitsLen"]
    with open(os.path.join(cur_dir, "drbg_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"returnedBitsLen" is too big.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["returnedBitsLen"] = 4096 + 1
    with open(os.path.join(cur_dir, "drbg_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"additionalInputLen" is too big.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["additionalInputLen"] = 1048576 + 1
    with open(os.path.join(cur_dir, "drbg_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"persoString" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["persoString"]
    with open(os.path.join(cur_dir, "drbg_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"persoString" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["persoString"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInput" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["persoString"]
    with open(os.path.join(cur_dir, "drbg_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"entropyInput" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["persoString"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_20.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"nonce" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["nonce"]
    with open(os.path.join(cur_dir, "drbg_21.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"nonce" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["nonce"] = "a" * (512 + 1)
    with open(os.path.join(cur_dir, "drbg_22.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"otherInput" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["otherInput"]
    with open(os.path.join(cur_dir, "drbg_23.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"otherInput" array is empty.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["otherInput"] = []
    with open(os.path.join(cur_dir, "drbg_24.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"additionalInput" for otherInput[0] is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    del other_input[0]["additionalInput"]
    with open(os.path.join(cur_dir, "drbg_25.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"additionalInput" for otherInput[0] string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    other_input[0]["additionalInput"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_26.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInput" for otherInput[0] is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    del other_input[0]["entropyInput"]
    with open(os.path.join(cur_dir, "drbg_27.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInput" for otherInput[0] string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    other_input[0]["entropyInput"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_28.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"additionalInput" for otherInput[1] is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    del other_input[1]["additionalInput"]
    with open(os.path.join(cur_dir, "drbg_29.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"additionalInput" for otherInput[1] string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    other_input[1]["additionalInput"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_30.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInput" for otherInput[1] is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    del other_input[1]["entropyInput"]
    with open(os.path.join(cur_dir, "drbg_31.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"entropyInput" for otherInput[1] string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    other_input = t["otherInput"]
    other_input[1]["entropyInput"] = "a" * (262144 + 1)
    with open(os.path.join(cur_dir, "drbg_32.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_drbg(file_in=None):
    """
    Main kas_ecc entry point.
    :param file_in: Name (str) of the drbg JSON input file.
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
