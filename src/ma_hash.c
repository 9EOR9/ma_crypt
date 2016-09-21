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

/** @file

   @brief
   Wrapper library for crypto hash functions.
   Works with the following tls/crypto libraries:
   OpenSSL, Nettle, Windows crypto.
   Supports the following hashing algorithms:
   MD5, SHA1, SHA128, SHA224, SHA256, SHA384, SHA512.
 */

#include "ma_hash.h"

static MA_HASH_TYPE ma_crypt_hash_hashtype(unsigned int hash_type)
{
  switch(hash_type) {
    case MA_HASH_MD5:
#ifdef HAVE_OPENSSL
      return EVP_md5();
#elif HAVE_NETTLE
      return &nettle_md5;
#elif HAVE_SCHANNEL
      return CALG_MD5;
#endif
      break;
    case MA_HASH_SHA1:
#ifdef HAVE_OPENSSL
      return EVP_sha1();
#elif HAVE_NETTLE
      return &nettle_sha1;
#elif HAVE_SCHANNEL
      return CALG_SHA1;
#endif    
      break;
    case MA_HASH_SHA224:
#ifdef HAVE_OPENSSL    
      return EVP_sha224();
#elif HAVE_NETTLE
      return &nettle_sha224;
#elif HAVE_SCHANNEL
      return -1;
#endif
      break;
    case MA_HASH_SHA256:
#ifdef HAVE_OPENSSL    
      return EVP_sha256();
#elif HAVE_NETTLE
      return &nettle_sha256;
#elif HAVE_SCHANNEL
      return CALG_SHA_256;
#endif
      break;
    case MA_HASH_SHA384:
#ifdef HAVE_OPENSSL    
      return EVP_sha384();
#elif HAVE_NETTLE
      return &nettle_sha384;
#elif HAVE_SCHANNEL
      return CALG_SHA_384;
#endif
      break;
    case MA_HASH_SHA512:
#ifdef HAVE_OPENSSL    
      return EVP_sha512();
#elif HAVE_NETTLE
      return &nettle_sha512;
#elif HAVE_SCHANNEL
      return CALG_SHA_512;
#endif
      break;
  }
  /* unsupported hash */
#ifdef HAVE_SCHANNEL
  return -1;
#else    
  return NULL;
#endif
}

static MA_HASH_CTX ma_crypt_hash_new(unsigned int hash_type)
{
  _MA_HASH_CTX ctx;
  MA_HASH_TYPE evp_hash;
  evp_hash= ma_crypt_hash_hashtype(hash_type);
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (evp_hash && (ctx= EVP_MD_CTX_new()))
#else
    if (evp_hash && (ctx= EVP_MD_CTX_create()))
#endif
    {
      EVP_DigestInit_ex(ctx, evp_hash, NULL);
      return (void *)ctx;
    }
#elif HAVE_NETTLE
  if (evp_hash && (ctx= (MA_HASH_CTX)malloc(sizeof(struct st_nettle_hash_ctx))))
  {
    ctx->ctx= malloc(evp_hash->context_size);
    ctx->hash= evp_hash;
    ctx->hash->init(ctx->ctx);
    return (void *)ctx;
  }
#elif HAVE_SCHANNEL
  if (evp_hash != -1 && (ctx= (MA_HASH_CTX)calloc(1, sizeof(struct st_hash_ctx))))
  {
    if(CryptAcquireContext(&ctx->hCryptProv,NULL,NULL,
          PROV_RSA_AES, CRYPT_VERIFYCONTEXT))

    {
      if (!CryptCreateHash(ctx->hCryptProv, evp_hash, 0, 0, &ctx->hHash))
      {
        CryptReleaseContext(ctx->hCryptProv, 0);
        free(ctx);
        return NULL;
      }
      return (void *)ctx;
    }
    else
      free(ctx);
  }
#endif
  return NULL;
}

static void ma_crypt_hash_input(MA_HASH_CTX hash_ctx,
                                const unsigned char *buf,
                                size_t len)
{
  _MA_HASH_CTX ctx= (_MA_HASH_CTX)hash_ctx;
#ifdef HAVE_OPENSSL
  EVP_DigestUpdate(ctx, buf, len);
#elif HAVE_NETTLE
  ctx->hash->update(ctx->ctx, len, buf);
#elif HAVE_SCHANNEL
  CryptHashData(ctx->hHash, buf, len, 0);
#endif  
}

static void ma_crypt_hash_result(MA_HASH_CTX hash_ctx, unsigned char *digest)
{
  _MA_HASH_CTX ctx= (_MA_HASH_CTX)hash_ctx;
#ifdef HAVE_OPENSSL
  EVP_DigestFinal_ex(ctx, digest, NULL);
#elif HAVE_NETTLE
  ctx->hash->digest(ctx->ctx, ctx->hash->digest_size, digest);
#elif HAVE_SCHANNEL
  unsigned long len;
  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);
#endif
}

static void ma_crypt_hash_deinit(MA_HASH_CTX hash_ctx)
{
  _MA_HASH_CTX ctx= (_MA_HASH_CTX)hash_ctx;
  if (!ctx)
    return;
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_MD_CTX_free(ctx);
#else
  EVP_MD_CTX_destroy(ctx);
#endif
#elif HAVE_NETTLE
  if (ctx) {
    free(ctx->ctx);
    free(ctx);
  }
#elif HAVE_SCHANNEL
  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);
  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
  free(ctx);
#endif
}

/**
  @brief return digest size for given hash algorithm

  @param hash_alg [in]   hashing hash_alg

  @return                length of digest                         
 */
size_t ma_hash_digest_size(unsigned int hash_alg)
{
  switch (hash_alg) {
    case MA_HASH_MD5:
      return 16;
    case MA_HASH_SHA1:
      return 20;
    case MA_HASH_SHA224:
      return 28;
    case MA_HASH_SHA256:
      return 32;
    case MA_HASH_SHA384:
      return 48;
    case MA_HASH_SHA512:
      return 64;
    default:
      return 0;  
  }
}

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
              unsigned char *digest, ...)
{
  va_list args;
  MA_HASH_CTX ctx;
  const unsigned char *str;

  if (!(ctx= ma_crypt_hash_new(hash_alg)))
    return;
  va_start(args, digest);

  for (str= va_arg(args, const unsigned char*); str; 
      str= va_arg(args, const unsigned char*))
    ma_crypt_hash_input(ctx, str, va_arg(args, size_t));

  ma_crypt_hash_result(ctx, digest);
  ma_crypt_hash_deinit(ctx);
  va_end(args);
}

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
             size_t length)
{
  ma_hashv(hash_alg, digest, buffer, length, NULL, 0);
}

/**
  @brief wrapper function to acquire a context for hash
  calculations

  @param hash_alg [in]   hashing hash_alg

  @return                 hash context                         
 */
MA_HASH_CTX ma_hash_new(unsigned int hash_alg)
{
  return ma_crypt_hash_new(hash_alg);
}

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param ctx [in]       hash context
  @param buffer [in]    data buffer
  @param len [in]       size of buffer

  @return               void
*/
void ma_hash_input(MA_HASH_CTX ctx, const char *buffer, size_t len)
{
  ma_crypt_hash_input(ctx, buffer, len);
}

/**
  @brief retrieves the hash value from hash context 

  @param ctx [in]       hash context
  @param digest [in]    digest containing hash value

  @return               void
*/
void ma_hash_result(MA_HASH_CTX ctx,
                    unsigned char *digest)
{
  ma_crypt_hash_result(ctx, digest);
}

/**
  @brief deallocates hash context which was previoulsy allocated by
  ma_hash_new

  @param ctx [in]       hash context

  @return               void
 */
void ma_hash_free(MA_HASH_CTX ctx)
{
  ma_crypt_hash_deinit(ctx);
}
