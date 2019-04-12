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
    def __init__(self, comp=False):
        self.comp = comp
        self.got_it = False

    def keep(self, obj):
        """
        Take a testGroup dict, and decide whether to keep or remove.
        We only want the VAL because it includes more fields.
        :param obj: testGroup dict
        :return: True to keep
        :return: False to remove
        """
        if not self.comp:
            pass
        else:
            if obj["testType"] != "VAL":
                # Only want VAL for Component mode
                return False

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

def ref_last_testgroup(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[7]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[7]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test


def gen_comp(j=None):
    if j:
        # Regen basefile
        # This is a clean file. All of the JSON should be correct.
        with open(os.path.join(cur_dir, "kas_ffc_comp.json"), "w") as fp:
            json.dump(j, fp, indent=2)
    else:
        # Load the basefile
        with open(os.path.join(cur_dir, "kas_ffc_comp.json"), "r") as f:
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

    with open(os.path.join(cur_dir, "kas_ffc_comp_21.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["hashZIut"]

    with open(os.path.join(cur_dir, "kas_ffc_comp_22.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # Trim the list!
    ##
    trim = Trim(comp=True)
    trim.run(j)

    # The key:"algorithm" is missing.
    s = copy.deepcopy(j)
    del s[1]["algorithm"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"mode" is wrong.
    s = copy.deepcopy(j)
    s[1]["mode"] = "my" + s[1]["mode"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"testType" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["testType"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"testType" is wrong.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["testType"] = "my" + tg["testType"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"hashAlg" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["hashAlg"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"hashAlg" is wrong.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["hashAlg"] = "my" + tg["hashAlg"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"p" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["p"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"p" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["p"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"q" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["q"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"q" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["q"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_10.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"g" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del tg["g"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_11.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"g" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    tg["g"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_12.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"ephemeralPublicServer" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["ephemeralPublicServer"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_13.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"ephemeralPublicServer" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["ephemeralPublicServer"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_14.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"ephemeralPrivateIut" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["ephemeralPrivateIut"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_15.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"ephemeralPrivateIut" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["ephemeralPrivateIut"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_16.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"ephemeralPublicIut" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["ephemeralPublicIut"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_17.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"ephemeralPublicIut" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["ephemeralPublicIut"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_18.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The key:"hashZIut" is missing.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    del t["hashZIut"]
    with open(os.path.join(cur_dir, "kas_ffc_comp_19.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # The value for key:"hashZIut" string is too long.
    s = copy.deepcopy(j)
    tg, t = ref_testgroup_and_test(s)
    t["hashZIut"] = "a" * 1025
    with open(os.path.join(cur_dir, "kas_ffc_comp_20.json"), "w") as fp:
        json.dump(s, fp, indent=2)


def main_kas_ffc_comp(file_in=None):
    """
    Main kas_ffc entry point.
    :param file_in: Name (str) of the kas_ffc_comp JSON input file.
    :return: 0 for success
    :return: 1 for fail
    """
    global logger

    logger = logging.getLogger(__name__)

    if file_in:
        with open(file_in, "r") as f:
            # Load the JSON into j object (should be a list)
            j = json.load(f)
            gen_comp(j)
    else:
        gen_comp()
