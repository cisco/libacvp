"""
*
* Copyright (c) 2018, Cisco Systems, Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
    test_group = test_groups[2]

    return test_group

def ref_last_test(single):
    # Get ref to last testGroups item
    test_groups = single[1]["testGroups"]
    test_group = test_groups[2]

    # Get ref to last test item
    tests = test_group["tests"]
    test = tests[0]

    return test


def gen_sigver(j):
    # This is a clean file. All of the JSON should be correct.
    with open(os.path.join(cur_dir, "rsa_sigver.json"), "w") as fp:
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

    with open(os.path.join(cur_dir, "rsa_sigver_8.json"), "w") as fp:
        json.dump(s, fp, indent=2)


    ##
    # The value for key:"msg" is missing in the last test_case
    ##
    s = copy.deepcopy(single)
    t = ref_last_test(s)
    del t["message"]

    with open(os.path.join(cur_dir, "rsa_sigver_9.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    # Trim the testGroups to a single item and get a ref
    single = copy.copy(j)
    test_groups = single[1]["testGroups"]
    test_groups[1:] = []
    # Trim the tests to a single item and get a ref
    tests = test_groups[0]["tests"]
    tests[1:] = []

    ##
    # only need to add sigver tests for cases that would be unique
    # to sigver since siggen shared code tests a lot of negative
    # cases already
    ##

    ##
    # The key:"e" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["e"]
    with open(os.path.join(cur_dir, "rsa_sigver_1.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"n" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["n"]
    with open(os.path.join(cur_dir, "rsa_sigver_2.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"signature" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del t["signature"]
    with open(os.path.join(cur_dir, "rsa_sigver_3.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"signature" is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    t["signature"] = "a" * (2048 + 1) # ACVP_RSA_SIGNATURE_MAX
    with open(os.path.join(cur_dir, "rsa_sigver_4.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"e" is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["e"] = "a" * (1024 + 1) # ACVP_RSA_EXP_LEN_MAX
    with open(os.path.join(cur_dir, "rsa_sigver_5.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"n" is too long.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    tg["n"] = "a" * (1024 + 1) # ACVP_RSA_EXP_LEN_MAX
    with open(os.path.join(cur_dir, "rsa_sigver_6.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    ##
    # The value for key:"tgId" is missing.
    ##
    s = copy.deepcopy(single)
    tg, t = ref_testgroup_and_test(s)
    del tg["tgId"]
    with open(os.path.join(cur_dir, "rsa_sigver_7.json"), "w") as fp:
        json.dump(s, fp, indent=2)

    return 0


def main_rsa_sigver(file_in):
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
                if gen_sigver(j):
                    return 1
            except json.JSONDecodeError:
                logger.error("JSONDecodeError for file_in=%s", file_in)
                return 1
    except IOError:
        logger.error("IOError for file_in=%s", file_in)
        return 1


    return 0
