The test framework for the C ACVP library leverages Criterion --> https://github.com/Snaipe/Criterion

- update the test_env.sh script
- 'source test_env.sh'

Running tests:
make clean && make
./runtest

You can see more detail using:
./runtest --verbose

Or filter for specific tests, for example:
./runtest --verbose --filter *APP_KAS_FFC_HANDLER*

More features are supported, see the Criterion docs for more:
https://criterion.readthedocs.io/en/master/

JSON Collateral:

    All examples json messages are kept in the 'json' directory. Most
    algorithms have corresponding scripts that help build the corrupt
    json from a clean json file. These shouldn't need to change unless
    changes are made to the algorithm specifications.

    The json/generate_json.py script can be used to regenerate json files
    if necessary.


OR run using Docker
move to docker directory
follow README instructions