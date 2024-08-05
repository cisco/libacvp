# Overview
This directory contains code for harnesses for different Implementations Under Test (IUTs)
supported by acvp_app. Acvp_app will support testing ONE harness per build; which harness is built
will be determined when running the configure command.

The openssl directory contains harnesses for OpenSSL version 3.0 and later.

The stub directory is not compiled by default and includes some template functions with
descriptions meant to help people implement their own harnesses for IuTs.

## Structure for Harness Code

Even though harness code will be directly compiled into the app, we will follow a specific API
structure meant to help keep IUT logic separate from usage and protocol logic. Every IUT harness
will be expected to provide these functions:

```
/* Perform any setup needed to initialize the given IUT */
ACVP_RESULT iut_setup(APP_CONFIG *cfg);
```
```
/* Register the capabilities of the given IUT */
ACVP_RESULT iut_register_capabilities(ACVP_CTX *ctx, APP_CONFIG *cfg);
```
```
/** Frees any memory associated with the harness AFTER all tests are complete */
ACVP_RESULT iut_cleanup(void);
```
```
/* prints all relevant IuT version information to stdout */
void iut_print_version(APP_CONFIG *cfg);
```

Source for each IUT must be kept in its own folder in the implementations directory. Different
versions of an IUT should be handled in whatever way is most readable. **Every IUT and version
of IUT with its own capability registration must have their registrations kept in separate places,
even if the differences are small.** This helps ensure that capability registrations do not change
after an implementation has received any certification.

## Contributing Harness Code

libacvp is not accepting additional harnesses for our repo at this time. We may consider it
in the future for significant open source implementations if we are able to determine a good framework
for support and maintenance obligations.

We will happily accept PRs making improvements to existing harness code, provided they do not alter
algorithm registrations for already-certified implementations.
