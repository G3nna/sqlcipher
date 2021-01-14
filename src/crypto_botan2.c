/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** Copyright (c) 2021, Rohde & Schwarz Cybersecurity GmbH
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN CRYPTO_BOTAN_2 */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_BOTAN_2

#include "crypto.h"
#include "sqliteInt.h"
#include "sqlcipher.h"

#include <botan/build.h>
#include <botan/ffi.h>

#if BOTAN_VERSION_MAJOR < 2 || (BOTAN_VERSION_MAJOR == 2 && BOTAN_VERSION_MINOR < 8)
  #error "The provided botan-2 version is too old (< 2.8.0)"
#endif

#if !defined(BOTAN_HAS_FFI)
  #error "The provided botan-2 version does not provide FFI"
#endif

#if !defined(BOTAN_HAS_KDF2)
  #error "The provided botan-2 version does not provide KDF2"
#endif

#if !defined(BOTAN_HAS_SHA1)
  #error "The provided botan-2 version does not provide SHA1"
#endif

#if !defined(BOTAN_HAS_SHA2_32)
  #error "The provided botan-2 version does not provide SHA256"
#endif

#if !defined(BOTAN_HAS_SHA2_64)
  #error "The provided botan-2 version does not provide SHA512"
#endif

#if !defined(BOTAN_HAS_AES)
  #error "The provided botan-2 version does not provide AES"
#endif

#if !defined(BOTAN_HAS_HMAC)
  #error "The provided botan-2 version does not provide HMAC"
#endif

#if !defined(BOTAN_HAS_MODE_CBC)
  #error "The provided botan-2 version does not provide CBC"
#endif

#if !defined(SQLCIPHER_BOTAN2_RNG)
  #define SQLCIPHER_BOTAN2_RNG user
#endif

#define SQLCIPHER_BOTAN2_RNG_XSTR(x) SQLCIPHER_BOTAN2_RNG_STR(x)
#define SQLCIPHER_BOTAN2_RNG_STR(x) #x

static botan_rng_t rng = NULL;
static volatile unsigned int botan_ref_count = 0;

static int sqlcipher_botan_activate(void *ctx) {
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  int rc = 0;
  if (botan_ref_count == 0) {
    rc = botan_rng_init(&rng, SQLCIPHER_BOTAN2_RNG_XSTR(SQLCIPHER_BOTAN2_RNG));
  }
  botan_ref_count++;
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  return rc == 0 ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_botan_deactivate(void *ctx) {
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  botan_ref_count--;
  int rc = 0;
  if (botan_ref_count == 0) {
    rc = botan_rng_destroy(rng);
    rng = NULL;
  }
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  return rc == 0 ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_botan_add_random(void *ctx, void *buffer, int length) {
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  int rc = botan_rng_add_entropy(rng, buffer, length);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  return rc == 0 ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_botan_random(void *ctx, void *buffer, int length) {
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  int rc = botan_rng_get(rng, (uint8_t *) buffer, length);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  return rc == 0 ? SQLITE_OK : SQLITE_ERROR;
}

static const char* sqlcipher_botan_get_provider_name(void *ctx) {
  return "botan-2";
}

static int sqlcipher_botan_get_hmac_sz(void *ctx, int algorithm) {
  char *algo;
  switch (algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      algo = "HMAC(SHA-1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      algo = "HMAC(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      algo = "HMAC(SHA-512)";
      break;
    default:
      return 0;
  }

  botan_mac_t mac;
  if (botan_mac_init(&mac, algo, 0) != 0) {
    return 0;
  }

  size_t mac_output_len = 0;
  if (botan_mac_output_length(mac, &mac_output_len) != 0) {
    botan_mac_destroy(mac);
    return 0;
  }

  if (botan_mac_destroy(mac) != 0) {
    return 0;
  }

  return mac_output_len;
}

static int sqlcipher_botan_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  char *algo;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      algo = "HMAC(SHA-1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      algo = "HMAC(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      algo = "HMAC(SHA-512)";
      break;
    default:
      return SQLITE_ERROR;
  }

  botan_mac_t mac;
  if (botan_mac_init(&mac, algo, 0) != 0) {
    return SQLITE_ERROR;
  }

  if (botan_mac_set_key(mac, hmac_key, key_sz) != 0) {
    botan_mac_destroy(mac);
    return SQLITE_ERROR;
  }

  if (botan_mac_update(mac, in, in_sz) != 0) {
    botan_mac_destroy(mac);
    return SQLITE_ERROR;
  }

  if (botan_mac_update(mac, in2, in2_sz) != 0) {
    botan_mac_destroy(mac);
    return SQLITE_ERROR;
  }

  if (botan_mac_final(mac, out) != 0) {
    botan_mac_destroy(mac);
    return SQLITE_ERROR;
  }

  if (botan_mac_destroy(mac) != 0) {
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

static int sqlcipher_botan_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
 char *algo;
 switch (algorithm) {
   case SQLCIPHER_HMAC_SHA1:
     algo = "PBKDF2(SHA-1)";
     break;
   case SQLCIPHER_HMAC_SHA256:
     algo = "PBKDF2(SHA-256)";
     break;
   case SQLCIPHER_HMAC_SHA512:
     algo = "PBKDF2(SHA-512)";
     break;
   default:
     return SQLITE_ERROR;
 }

 if (botan_pwdhash(
             algo,
             workfactor,
             0,
             0,
             key, key_sz,
             (const char *) pass, pass_sz,
             salt, salt_sz) != 0) {
     return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

static const char* sqlcipher_botan_get_cipher(void *ctx) {
  return "AES-256/CBC/NoPadding";
}

static int sqlcipher_botan_get_key_sz(void *ctx) {
  botan_cipher_t cipher;
  if (botan_cipher_init(
              &cipher,
              sqlcipher_botan_get_cipher(ctx),
              BOTAN_CIPHER_INIT_FLAG_ENCRYPT) != 0) {
      return 0;
  }

  size_t min_keylen = 0;
  size_t max_keylen = 0;
  size_t mod_keylen = 0;
  if (botan_cipher_get_keyspec(cipher, &min_keylen, &max_keylen, &mod_keylen) != 0) {
      botan_cipher_destroy(cipher);
      return 0;
  }

  if (botan_cipher_destroy(cipher) != 0) {
      return 0;
  }

  return max_keylen;
}

static int sqlcipher_botan_get_iv_sz(void *ctx) {
  return 16;
}

static int sqlcipher_botan_get_block_sz(void *ctx) {
  return 16;
}

static int sqlcipher_botan_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  botan_cipher_t cipher;
  if (botan_cipher_init(
                  &cipher,
                  sqlcipher_botan_get_cipher(ctx),
                  ((mode == CIPHER_ENCRYPT) ? BOTAN_CIPHER_INIT_FLAG_ENCRYPT : BOTAN_CIPHER_INIT_FLAG_DECRYPT)) != 0) {
      return SQLITE_ERROR;
  }

  if (botan_cipher_set_key(cipher, key, key_sz) != 0) {
      botan_cipher_destroy(cipher);
      return SQLITE_ERROR;
  }

  if (botan_cipher_start(cipher, iv, sqlcipher_botan_get_iv_sz(ctx)) != 0) {
      botan_cipher_destroy(cipher);
      return SQLITE_ERROR;
  }

  size_t input_read = 0;
  size_t output_written = 0;
  if (botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL, out, in_sz, &output_written, in, in_sz, &input_read) != 0) {
      botan_cipher_destroy(cipher);
      return SQLITE_ERROR;
  }

  if (botan_cipher_destroy(cipher) != 0) {
      return SQLITE_ERROR;
  }

  if (input_read <= 0 || input_read != in_sz || input_read != output_written) {
      return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

static int sqlcipher_botan_ctx_init(void **ctx) {
  sqlcipher_botan_activate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_ctx_free(void **ctx) {
  sqlcipher_botan_deactivate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_fips_status(void *ctx) {
  return 0;
}

static const char* sqlcipher_botan_get_provider_version(void *ctx) {
  return botan_version_string();
}

int sqlcipher_botan_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_botan_activate;
  p->deactivate = sqlcipher_botan_deactivate;
  p->get_provider_name = sqlcipher_botan_get_provider_name;
  p->random = sqlcipher_botan_random;
  p->hmac = sqlcipher_botan_hmac;
  p->kdf = sqlcipher_botan_kdf;
  p->cipher = sqlcipher_botan_cipher;
  p->get_cipher = sqlcipher_botan_get_cipher;
  p->get_key_sz = sqlcipher_botan_get_key_sz;
  p->get_iv_sz = sqlcipher_botan_get_iv_sz;
  p->get_block_sz = sqlcipher_botan_get_block_sz;
  p->get_hmac_sz = sqlcipher_botan_get_hmac_sz;
  p->ctx_init = sqlcipher_botan_ctx_init;
  p->ctx_free = sqlcipher_botan_ctx_free;
  p->add_random = sqlcipher_botan_add_random;
  p->fips_status = sqlcipher_botan_fips_status;
  p->get_provider_version = sqlcipher_botan_get_provider_version;
  return SQLITE_OK;
}

#undef SQLCIPHER_BOTAN2_RNG_XSTR
#undef SQLCIPHER_BOTAN2_RNG_STR
#endif
#endif
/* END CRYPTO_BOTAN_2 */

