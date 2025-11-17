The test framework for the C ACVP library leverages Unity --> https://github.com/ThrowTheSwitch/Unity

Unity is a unit testing framework for C. The license for Unity can be found in test/unity/LICENSE.md.
NOTE: Unity has been slightly modified for our uses within this project.

## Building

To enable the unit tests binary (named "runtest"), the project configure must be run with --enable-unit-tests

```
./configure --enable-unit-tests --with-ssl-dir=<path to ssl dir> --with-libcurl-dir=<path to curl dir>
make clean
make
```

If the project is configured with --disable-app or --disable-lib, only the relevant unit tests will be included.

## Running Tests

```
./test/runtest
```

You can see more detailed test output using:
```
./test/runtest -v
```

The runtest executable can be made to run only certain TEST_GROUPS using the -g argument:
```
./test/runtest -g <TEST_GROUP name>
```

For example:
```
./test/runtest -g AES -v
```

## Contributing

Before opening a pull request that modifies unit tests or adds new test coverage,
please ensure that:

1. All unit tests pass
2. No memory leaks are reported (use valgrind or similar tools)
3. All memory allocations are properly cleaned up
4. All pointers are properly set up and torn down in setup/teardown functions

New library features should include corresponding unit tests that follow these
guidelines.
