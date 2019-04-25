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


def ref_testgroup_and_test(single):
    # Get ref to single testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[35]

    # Get ref to single test item
    tests = test_group["tests"]
    test = tests[0]

    return test_group, test

def ref_last_testgroup(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[35]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[35]

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


def convert_to_gcm(s):
    if s[1]["algorithm"] == "ACVP-AES-GCM":
        # Already GCM mode
        return

    s[1]["algorithm"] = "ACVP-AES-GCM"

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivGen"] = "internal"
    tg["ivGenMode"] = "8.2.1"
    tg["ivLen"] = 96
    tg["ptLen"] = 0
    tg["aadLen"] = 0
    tg["tagLen"] = 96
    t["aad"] = ""

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    tg["ivGen"] = "internal"
    tg["ivGenMode"] = "8.2.1"
    tg["ivLen"] = 96
    tg["ptLen"] = 0
    tg["aadLen"] = 0
    tg["tagLen"] = 96
    t["aad"] = ""
    t["iv"] = "CD26CE857B0CDCDEE932FFC0"
    t["tag"] = "D7A8C84F848BA472165472A4"


def convert_to_ctr(s):
    if s[1]["algorithm"] == "ACVP-AES-CTR":
        # Already CTR mode
        return

    s[1]["algorithm"] = "ACVP-AES-CTR"

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["incrementalCounter"] = True
    tg["overflowCounter"] = True


def convert_to_ccm(s):
    if s[1]["algorithm"] == "ACVP-AES-CCM":
        # Already CCM mode
        return

    s[1]["algorithm"] = "ACVP-AES-CCM"

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 56
    tg["ptLen"] = 192
    tg["aadLen"] = 0
    tg["tagLen"] = 128
    t["aad"] = ""
    t["pt"] = "1BA6CBDC341BAFE3F50C17C30932984A1D558C0A19E40D73"
    t["iv"] = "5C41BE4BC85191"

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    tg["ivLen"] = 56
    tg["ptLen"] = 0
    tg["aadLen"] = 0
    tg["tagLen"] = 32
    t["aad"] = ""
    t["iv"] = "EE24D187504BB0"


def gen(j=None):
    if j:
        # Regen the basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "aes.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "aes.json"), "r") as f:
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

    with open(os.path.join(cur_dir, "aes_33.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["iv"]

    with open(os.path.join(cur_dir, "aes_34.json"), "w") as fp:
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
    with open(os.path.join(cur_dir, "aes_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"direction" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["direction"]
    with open(os.path.join(cur_dir, "aes_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"direction" is wrong.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["direction"] = "my" + tg["direction"]
    with open(os.path.join(cur_dir, "aes_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"testType" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["testType"]
    with open(os.path.join(cur_dir, "aes_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"testType" is wrong.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["testType"] = "my" + tg["testType"]
    with open(os.path.join(cur_dir, "aes_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"keyLen" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["keyLen"]
    with open(os.path.join(cur_dir, "aes_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"keyLen" is wrong.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["keyLen"] = 257
    with open(os.path.join(cur_dir, "aes_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"payloadLen" is too big.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["payloadLen"] = 131073 # ACVP_SYM_PT_BIT_MAX + 1
    with open(os.path.join(cur_dir, "aes_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"ivLen" is missing.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["ivLen"]
    with open(os.path.join(cur_dir, "aes_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ivLen" is too small (GCM).
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 7
    with open(os.path.join(cur_dir, "aes_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ivLen" is too big (GCM).
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 1025
    with open(os.path.join(cur_dir, "aes_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ivLen" is too small (CCM).
    ##
    s = copy.deepcopy(j)
    convert_to_ccm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 55
    with open(os.path.join(cur_dir, "aes_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ivLen" is too big (CCM).
    ##
    s = copy.deepcopy(j)
    convert_to_ccm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 105
    with open(os.path.join(cur_dir, "aes_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ivLen" is not an increment of 8 (CCM).
    ##
    s = copy.deepcopy(j)
    convert_to_ccm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["ivLen"] = 103
    with open(os.path.join(cur_dir, "aes_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"tagLen" is too small.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["tagLen"] = 3
    with open(os.path.join(cur_dir, "aes_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"tagLen" is too big.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["tagLen"] = 129
    with open(os.path.join(cur_dir, "aes_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"aadLen" is too big.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["aadLen"] = 65537
    with open(os.path.join(cur_dir, "aes_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"key" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["key"]
    with open(os.path.join(cur_dir, "aes_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"key" string is too long.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["key"] = "a" * 129
    with open(os.path.join(cur_dir, "aes_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"pt" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del t["pt"]
    with open(os.path.join(cur_dir, "aes_20.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"pt" string is too long.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    t["pt"] = "a" * 32769
    with open(os.path.join(cur_dir, "aes_21.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"ct" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, DECRYPT)
    del t["ct"]
    with open(os.path.join(cur_dir, "aes_22.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"ct" string is too long.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, DECRYPT)
    t["ct"] = "a" * 32769
    with open(os.path.join(cur_dir, "aes_23.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tag" is missing.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    del t["tag"]
    with open(os.path.join(cur_dir, "aes_24.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"tag" string is too long.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    t["tag"] = "a" * 33
    with open(os.path.join(cur_dir, "aes_25.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"iv" is missing.
    ##
    s = copy.deepcopy(j)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    del t["iv"]
    with open(os.path.join(cur_dir, "aes_26.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"iv" string is too long.
    ##
    s = copy.deepcopy(j)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    t["iv"] = "a" * 257
    with open(os.path.join(cur_dir, "aes_27.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"aad" is missing.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    del t["aad"]
    with open(os.path.join(cur_dir, "aes_28.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"aad" string is too long.
    ##
    s = copy.deepcopy(j)
    convert_to_gcm(s)

    tg, t = ref_testgroup_and_test(s, DECRYPT)
    t["aad"] = "a" * 16385
    with open(os.path.join(cur_dir, "aes_29.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The key:"tgId" is missing.
    ##
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "aes_30.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The boolean for "incrementalCounter" is not a boolean for ACVP-AES-CTR
    ##
    s = copy.deepcopy(j)
    convert_to_ctr(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["incrementalCounter"] = "maybe"
    tg["testType"] = "CTR"
    with open(os.path.join(cur_dir, "aes_31.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The boolean for "overflowCounter" is not a boolean for ACVP-AES-CTR
    ##
    s = copy.deepcopy(j)
    convert_to_ctr(s)

    tg, t = ref_testgroup_and_test(s, ENCRYPT)
    tg["overflowCounter"] = "maybe"
    tg["testType"] = "CTR"
    with open(os.path.join(cur_dir, "aes_32.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_aes(file_in=None):
    """
    Main aes entry point.
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
