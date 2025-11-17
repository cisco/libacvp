/*
   hmac_sha256.c
   Originally written by https://github.com/h5p9sl
   LIBACVP NOTE: Original code modified to include PR #7 at https://github.com/h5p9sl/hmac_sha256/pull/7.
   Code also modified to use safeC memory calls.
   This code is not thoroughly vetted and should NOT be used for any security purposes. It should ONLY be used for
   TOTP generation for the already-secured ACVP protocol communications.
 */

#include "hmac_sha256.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>
#include "safe_lib.h"

#define SHA256_BLOCK_SIZE 64

// LOCAL FUNCTIONS

// Concatenate X & Y, return hash.
static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen);

// Wrapper for sha256
static void* sha256(const void* data,
                    const size_t datalen,
                    void* out,
                    const size_t outlen);

// Declared in hmac_sha256.h
size_t hmac_sha256(const void* key,
                   const size_t keylen,
                   const void* data,
                   const size_t datalen,
                   void* out,
                   const size_t outlen) {
  uint8_t k[SHA256_BLOCK_SIZE];
  uint8_t k_ipad[SHA256_BLOCK_SIZE];
  uint8_t k_opad[SHA256_BLOCK_SIZE];
  uint8_t ihash[SHA256_HASH_SIZE];
  uint8_t ohash[SHA256_HASH_SIZE];
  size_t sz;
  int i;

  memset_s(k, sizeof(k), 0, sizeof(k));
  memset_s(k_ipad, sizeof(k_ipad), 0x36, sizeof(k_ipad));
  memset_s(k_opad, sizeof(k_opad), 0x5c, sizeof(k_opad));

  if (keylen > SHA256_BLOCK_SIZE) {
    // If the key is larger than the hash algorithm's
    // block size, we must digest it first.
    sha256(key, keylen, k, sizeof(k));
  } else {
    memcpy_s(k, sizeof(k), key, keylen);
  }

  for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
    k_ipad[i] ^= k[i];
    k_opad[i] ^= k[i];
  }

  // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
  //      `H(K XOR opad, H(K XOR ipad, data))`
  H(k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
  H(k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

  sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
  memcpy_s(out, outlen, ohash, sz);
  return sz;
}

static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen) {

  size_t sz;
  Sha256Context ctx;
  SHA256_HASH hash;

  Sha256Initialise(&ctx);
  Sha256Update(&ctx, x, xlen);
  Sha256Update(&ctx, y, ylen);
  Sha256Finalise(&ctx, &hash);

  sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;

  if (memcpy_s(out, outlen, hash.bytes, sz) == EOK) {
    return out;
  } else {
    return NULL;
  }
}

static void* sha256(const void* data,
                    const size_t datalen,
                    void* out,
                    const size_t outlen) {
  size_t sz;
  Sha256Context ctx;
  SHA256_HASH hash;

  Sha256Initialise(&ctx);
  Sha256Update(&ctx, data, datalen);
  Sha256Finalise(&ctx, &hash);

  sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
  if (memcpy_s(out, outlen, hash.bytes, sz) == EOK) {
    return out;
  } else {
    return NULL;
  }
}
