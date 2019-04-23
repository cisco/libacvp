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


ENCRYPT = 1
DECRYPT = 2
cur_dir = os.path.dirname(__file__)


class Trim():
    def __init__(self):
        self.got_encrypt = False
        self.got_decrypt = False

    def keep(self, obj):
        """
        Take a testGroup dict, and decide whether to keep or remove.
        :param obj: testGroup dict
        :return: True to keep
        :return: False to remove
        """
        if obj["direction"] == "encrypt":
            if self.got_encrypt:
                return False
            else:
                # Trim the tests down to 1 item
                obj["tests"] = obj["tests"][:1]
                self.got_encrypt = True
                return True
        else:
            if self.got_decrypt:
                return False
            else:
                # Trim the tests down to 1 item
                obj["tests"] = obj["tests"][:1]
                self.got_decrypt = True
                return True

        # Remove everything else (including MCT to shave off time)
        return False

    def run(self, j_list):
        # Start from index 1 to avoid the version object
        test_groups = j_list[1]["testGroups"]

        tmp = [x for x in test_groups if self.keep(x)]
        j_list[1]["testGroups"] = tmp


def ref_last_testgroup(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[13]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[13]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test

def ref_testgroup_and_test(j_list, group_type=ENCRYPT):
    # Start from index 1 to avoid the version object
    test_groups = j_list[1]["testGroups"]

    # For all, skip the first entry (version object)
    if group_type == ENCRYPT:
        for obj in test_groups:
            if obj["direction"] == "encrypt" and obj["testType"] == "AFT":
                tg_obj = obj
                break
    elif group_type == DECRYPT:
        for obj in test_groups:
            if obj["direction"] == "decrypt" and obj["testType"] == "AFT":
                tg_obj = obj
                break
    else:
        raise ValueError("Invalid group_type")

    # Get ref to the selected testGroup obj
    test_group = obj

    # Get ref to single test item
    tests = test_group["tests"]
    test = tests[0]

    return test_group, test


def convert_to_ctr(s):
    if s[1]["algorithm"] == "ACVP-TDES-CTR":
        # Already CTR mode
        return

    s[1]["algorithm"] = "ACVP-TDES-CTR"

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["incrementalCounter"] = True
    tg["overflowCounter"] = True


def gen(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "des.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "des.json"), "r") as f:
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

    with open(os.path.join(cur_dir, "des_21.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["iv"]

    with open(os.path.join(cur_dir, "des_22.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # Trim the list!
    # Note, all MCT testType were removed in an effort to shave off time.
    ##
    trim = Trim()
    trim.run(j)

    ##
    # The value for key:"algorithm" is wrong.
    ##
    s = copy.deepcopy(j)
    s[1]["algorithm"] = "my" + s[1]["algorithm"]
    with open(os.path.join(cur_dir, "des_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"direction" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["direction"]
    with open(os.path.join(cur_dir, "des_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"direction" is wrong.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["direction"] = "my" + tg["direction"]
    with open(os.path.join(cur_dir, "des_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"testType" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["testType"]
    with open(os.path.join(cur_dir, "des_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"testType" is wrong.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["testType"] = "my" + tg["testType"]
    with open(os.path.join(cur_dir, "des_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key1" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["key1"]
    with open(os.path.join(cur_dir, "des_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"key1" string is wrong length.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["key1"] = "a" * 17
    with open(os.path.join(cur_dir, "des_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key2" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["key2"]
    with open(os.path.join(cur_dir, "des_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"key2" string is wrong length.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["key2"] = "a" * 17
    with open(os.path.join(cur_dir, "des_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key3" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["key3"]
    with open(os.path.join(cur_dir, "des_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"key3" string is wrong length.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["key3"] = "a" * 17
    with open(os.path.join(cur_dir, "des_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"pt" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["pt"]
    with open(os.path.join(cur_dir, "des_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"pt" string is too long.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["pt"] = "a" * 32769
    with open(os.path.join(cur_dir, "des_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"ct" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, DECRYPT)
    del t["ct"]
    with open(os.path.join(cur_dir, "des_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ct" string is too long.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, DECRYPT)
    t["ct"] = "a" * 32769
    with open(os.path.join(cur_dir, "des_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"iv" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    if s[1]["algorithm"] == "ACVP-TDES-ECB":
        # ECB doesn't have iv
        s[1]["algorithm"] = "ACVP-TDES-CBC"
    else:
        del t["iv"]

    with open(os.path.join(cur_dir, "des_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"iv" string is wrong length.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)

    if s[1]["algorithm"] == "ACVP-TDES-ECB":
        # ECB doesn't have iv
        s[1]["algorithm"] = "ACVP-TDES-CBC"

    t["iv"] = "a" * 257
    with open(os.path.join(cur_dir, "des_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "des_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The boolean for "incrementalCounter" is not a boolean for ACVP-TDES-CTR
    ##
    s = copy.deepcopy(j)
    convert_to_ctr(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["incrementalCounter"] = "maybe"
    tg["testType"] = "CTR"
    with open(os.path.join(cur_dir, "des_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The boolean for "overflowCounter" is not a boolean for ACVP-TDES-CTR
    ##
    s = copy.deepcopy(j)
    convert_to_ctr(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["overflowCounter"] = "maybe"
    tg["testType"] = "CTR"
    with open(os.path.join(cur_dir, "des_20.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_des(file_in=None):
    """
    Main des entry point.
    :param file_in: Name (str) of the des JSON input file.
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
