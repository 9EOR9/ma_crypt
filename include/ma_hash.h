/* Copyright (c) 2016 Georg Richter and MariaDB Corporation AB

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA */

#ifndef _ma_hash_h
#define _ma_hash_h

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

/** @file

   @brief
   Include file for for crypto hash functions.
*/

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
typedef EVP_MD_CTX *_MA_HASH_CTX;
typedef const EVP_MD *MA_HASH_TYPE;
#elif HAVE_NETTLE
#include <nettle/nettle-meta.h>
typedef const struct nettle_hash *MA_HASH_TYPE;
typedef struct st_nettle_hash_ctx {
  void *ctx;
  MA_HASH_TYPE hash;
} *_MA_HASH_CTX;
#elif HAVE_SCHANNEL
#include <windows.h>
#include <wincrypt.h>
struct st_hash_ctx {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
};
typedef struct st_hash_ctx *_MA_HASH_CTX;
typedef int MA_HASH_TYPE;
#endif

/**
  Context for hash operations
*/
typedef void *MA_HASH_CTX;

/*! hash type enumeration */
enum ma_hash_type {
  MA_HASH_MD5,     /*!< MD5 hash (128-bit, 16 bytes)  */
  MA_HASH_SHA1,    /*!< SHA1 hash (160-bit, 20 bytes) */
  MA_HASH_SHA224,  /*!< SHA224 hash (224-bit, 28 bytes) */
  MA_HASH_SHA256,  /*!< SHA256 hash (256-bit, 32 bytes) */
  MA_HASH_SHA384,  /*!< SHA384 hash (384-bit, 48 bytes) */
  MA_HASH_SHA512,  /*!< SHA512 hash (512-bit, 64 bytes) */
};

/* function prototypes */

/**
  @brief wrapper function to acquire a context for hash
  calculations

  @param hash_alg [in]   hashing hash_alg

  @return                 hash context                         
 */
MA_HASH_CTX ma_hash_new(unsigned int hash_alg);

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param ctx [in]       hash context
  @param buffer [in]    data buffer
  @param len [in]       size of buffer

  @return               void
*/

void ma_hash_input(MA_HASH_CTX ctx,
                   const char *buffer,
                   size_t len);

/**
  @brief retrieves the hash value from hash context 

  @param ctx [in]       hash context
  @param digest [in]    digest containing hash value

  @return               void
 */
void ma_hash_result(MA_HASH_CTX ctx, unsigned char *digest);

/**
  @brief deallocates hash context which was previoulsy allocated by
  ma_hash_new

  @param ctx [in]       hash context

  @return               void
 */
void ma_hash_free(MA_HASH_CTX ctx);
/**
  @brief wrapper function to compute hash from one or more
  buffers.

  @param hash_alg [in]   hashing hash_alg
  @param digest [out]     computed hash digest
  @param ... [in]         variable argument list containg touples of
  message and message lengths. Last parameter
  must be always NULL.

  @return                 void                         
 */

void ma_hashv(unsigned int hash_alg,
              unsigned char *digest, ...);
/**
  @brief wrapper function to compute hash from message buffer

  @param hash_alg [in]   hashing hash_alg
  @param digest [out]    computed hash digest
  @param buffer [in]     message buffer
  @param length [in]     length of message buffer

  @return                void                         
*/
void ma_hash(unsigned int hash_alg,
             unsigned char *digest,
             const char *buffer,
             size_t length);
/**
  @brief return digest size for given hash algorithm

  @param hash_alg [in]   hashing hash_alg

  @return                length of digest                         
 */
size_t ma_hash_digest_size(unsigned int hash_alg);

#ifdef __cplusplus
}
#endif
#endif /* _ma_hash_h */
