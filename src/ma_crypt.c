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


#include <stdlib.h>
#include <ma_crypt.h>
#include <assert.h>

#ifdef HAVE_NETTLE
static const void *ma_nettle_ciphers[MA_AES_CTR + 1][3]= {
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 },
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 },
  { &nettle_gcm_aes128, &nettle_gcm_aes192, &nettle_gcm_aes256 },
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 }
};
#elif HAVE_OPENSSL
#define make_aes_dispatcher(mode)                               \
  static inline const EVP_CIPHER *aes_ ## mode(uint klen)       \
  {                                                             \
    switch (klen) {                                             \
    case 16: return EVP_aes_128_ ## mode();                     \
    case 24: return EVP_aes_192_ ## mode();                     \
    case 32: return EVP_aes_256_ ## mode();                     \
    default: return 0;                                          \
    }                                                           \
  }

make_aes_dispatcher(ecb)
make_aes_dispatcher(cbc)
make_aes_dispatcher(ctr)
make_aes_dispatcher(gcm)

const EVP_CIPHER *(*openssl_ciphers[])(uint)= {
    aes_ecb, 
    aes_cbc,
    aes_gcm,
    aes_ctr
};

#elif HAVE_SCHANNEL
#endif

/*
  
  Simple PLKCS7 padding implementation, as described in RFC 5652
  The value of each byte added is the number of bytes added:

  03 04 05 01 02 04 01 F1 08 08 08 08 08 08 08 08

  If the length is a multiple of blocksize, and entire block of size
  block size will be added or removed

  if mode is set (=add) size of source must be at least len + blocksize
*/
 /* {{{ ma_pkcs7_pad */
static void ma_crypt_pkcs7_pad(unsigned char *src,
                               unsigned int *len,
                               unsigned int block_size,
                               unsigned char add)
{
  if (add)
  {
    unsigned int new_len;
    unsigned char pad;

    new_len= (*len / block_size + 1) * block_size;
    pad= new_len - *len;

    memset((char *)src + *len, pad, (size_t)pad);
    *len= new_len;
  } else {
    unsigned char pad[AES_BLOCK_SIZE];
    unsigned char pad_len= *(src - 1);
    memset(pad, pad_len, pad_len);
    if (memcmp(src - pad_len, pad, pad_len) == 0)
      *len= -pad_len;
  }
}
/* }}} */

/* {{{ ma_crypt_internal_pad */
static unsigned int ma_crypt_internal_pad(_MA_CRYPT_CTX ctx,
                                          unsigned char *src,
                                          unsigned char *dst,
                                          unsigned int *slen)
{
  unsigned char mask[AES_BLOCK_SIZE];
  unsigned int i, masklen, pad_len;
  pad_len= *slen % AES_BLOCK_SIZE;
  
  if (!pad_len)
    return 0;
  
  *slen-= pad_len;

  ma_crypt(MA_AES_ECB, MA_CRYPT_ENCRYPT | MA_CRYPT_NOPAD,
           ctx->iv, ctx->iv_len, mask, &masklen, ctx->key, ctx->key_len, 0, 0);
  for (i=0; i < pad_len; i++)
    dst[*slen + i]= src[*slen + i] ^ mask[i];
  return pad_len;
}
/* }}} */

/* {{{ ma_crypt_context_size */
unsigned int ma_crypt_context_size(unsigned int mode, unsigned int key_idx)
{
#ifdef HAVE_NETTLE
  if (mode == MA_AES_GCM)
    return ((struct nettle_aead *)ma_nettle_ciphers[mode][key_idx])->context_size;
  return ((struct nettle_cipher *)ma_nettle_ciphers[mode][key_idx])->context_size;
#elif HAVE_OPENSSL
#elif HAVE_SCHANNEL
#endif
}
/* }}} */

/*
  assigns a cipher to the given context. The cipher is 
  described by block mode (mode) and key length in bytes.
  Currently the following ciphers are supported:
    AES-ECB (128, 192 and 256 bits)
    AES-CBC (128, 192 and 256 bits)
    AES-GCM (128, 192 and 256 bits)
    AES-CTR (128, 192 and 256 bits)
*/    
/* {{{ ma_ctx_set_cipher */
static int ma_ctx_set_cipher(MA_CRYPT_CTX crypt_ctx,
                             enum ma_aes_mode mode,
                             unsigned int key_idx,
                             int flags __attribute__((unused)),
                             const unsigned char *key __attribute__((unused)),
                             const unsigned char *iv __attribute__((unused)))
{
  _MA_CRYPT_CTX ctx= (_MA_CRYPT_CTX)crypt_ctx;

  /* check if block cipher mode is valid */
  if (mode < MA_AES_ECB || mode > MA_AES_CTR)
    return MA_CRYPT_EINVCIPH;

#ifdef HAVE_NETTLE
  switch (mode) {
  case MA_AES_ECB:
  case MA_AES_CTR:
  case MA_AES_CBC:
    ctx->cipher.c= (struct nettle_cipher *)ma_nettle_ciphers[mode][key_idx];
    break;
  case MA_AES_GCM:
    ctx->cipher.a= (struct nettle_aead *)ma_nettle_ciphers[mode][key_idx];
    break;
  }
#elif HAVE_OPENSSL
  {
  if (!EVP_CipherInit(ctx->ctx, openssl_ciphers[mode](key_idx * 8 + 16),
                      key, iv, (flags & MA_CRYPT_ENCRYPT) ? 1 : 0))
    return MA_CRYPT_EINVCIPH;
  }
#elif HAVE_SCHANNEL
#endif
  ctx->mode= mode;
  return MA_CRYPT_OK;
}
/* }}} */

/* {{{ ma_crypt_new */
MA_CRYPT_CTX ma_crypt_new()
{
#ifdef HAVE_NETTLE
  MA_CRYPT_CTX ctx= calloc(1, sizeof(struct st_nettle_ctx));
#elif HAVE_OPENSSL
  MA_CRYPT_CTX ctx= calloc(1, sizeof(struct st_openssl_ctx));
#elif HAVE_SCHANNEL
#endif
  return ctx;
}
/* }}} */

/* {{{ ma_crypt_init */
int ma_crypt_init(MA_CRYPT_CTX crypt_ctx,
                  enum ma_aes_mode mode,
                  int flags,
                  const unsigned char *key,
                  unsigned int key_len,
                  const unsigned char *iv,
                  unsigned int iv_len)
{
  _MA_CRYPT_CTX ctx= (_MA_CRYPT_CTX)crypt_ctx;
  int rc= MA_CRYPT_OK;
  unsigned key_idx= (key_len - 16) / 8;

  /* check key size: valid values are 16, 24 and 32 */
  if (key_idx < 0 || key_idx > 2)
    return MA_CRYPT_EINVKEY;

  if (!ctx)
    return MA_CRYPT_EINVCTX;
#ifdef HAVE_NETTLE    
  if (!(ctx->ctx= malloc(ma_crypt_context_size(mode, key_idx))))
#elif HAVE_OPENSSL
  if (!(ctx->ctx= EVP_CIPHER_CTX_new()))
#elif HAVE_SCHANNEL
#endif
  {
    rc= MA_CRYPT_ENOMEM;
    goto fail;
  }

  if ((rc= ma_ctx_set_cipher(ctx, mode, key_idx, flags, key, iv)))
    goto fail;

#ifdef HAVE_NETTLE
  switch (mode) {
    case MA_AES_CTR:
      /* ctr mode uses encrypt key for en- and decryption */
      ctx->cipher.c->set_encrypt_key(ctx->ctx, key);
      break;
    case MA_AES_GCM:
      if (flags & MA_CRYPT_ENCRYPT)
        ctx->cipher.a->set_encrypt_key(ctx->ctx, key);
      else
        ctx->cipher.a->set_decrypt_key(ctx->ctx, key);

      if (iv && ctx->cipher.a->set_nonce)
        ctx->cipher.a->set_nonce(ctx->ctx, iv);
      if (iv_len > GCM_IV_SIZE)
        ctx->cipher.a->update(ctx->ctx, iv_len - GCM_IV_SIZE, iv + GCM_IV_SIZE);
      else
        ctx->cipher.a->update(ctx->ctx, 0, NULL);
      break;
    case MA_AES_CBC:
      if (iv_len != ctx->cipher.c->block_size)
      {
        rc= MA_CRYPT_EINVIV;
        goto fail;
      }
    default:
      if (flags & MA_CRYPT_ENCRYPT)
        ctx->cipher.c->set_encrypt_key(ctx->ctx, key);
      else
        ctx->cipher.c->set_decrypt_key(ctx->ctx, key);
      break;
  }
#elif HAVE_OPENSSL
  assert(EVP_CIPHER_CTX_key_length(ctx->ctx) == (int)key_len);
  if (flags & MA_CRYPT_NOPAD)
    EVP_CIPHER_CTX_set_padding(ctx->ctx, 0);
  if (mode == MA_AES_GCM)
  {
    int unused;
    int real_ivlen= EVP_CIPHER_CTX_iv_length(ctx->ctx);
    if (iv_len > real_ivlen && !EVP_CipherUpdate(ctx->ctx, NULL, &unused,
                                                 iv + real_ivlen,
                                                 iv_len - real_ivlen))
      return MA_CRYPT_BADDATA;
  }
#elif HAVE_SCHANNEL
#endif  
  /* save mode and flags */
  ctx->mode= mode;
  ctx->key= key;
  ctx->key_len= key_len;
  ctx->flags= flags;
  ctx->iv= iv;
  ctx->iv_len= iv_len;
  return 0;
fail:
  return 1;
}
/* }}} */

/* {{{ ma_crypt_update */
int ma_crypt_update(MA_CRYPT_CTX crypt_ctx,
                    const unsigned char *src,
                    unsigned int slen,
                    unsigned char *dst,
                    unsigned int *dlen)
{
  _MA_CRYPT_CTX ctx= (_MA_CRYPT_CTX)crypt_ctx;
  int rc= MA_CRYPT_OK;

  if (!ctx)
    return MA_CRYPT_EINVCTX;
  *dlen= 0;

#ifdef HAVE_NETTLE
  switch(ctx->mode) {
    case MA_AES_ECB:
    case MA_AES_CBC:
      if (ctx->flags & MA_CRYPT_NOPAD)
      {
        if (slen % AES_BLOCK_SIZE)
          *dlen= ma_crypt_internal_pad(ctx, (char *)src, dst, &slen);
        if (slen < AES_BLOCK_SIZE)
          return rc;
      }
      else if (ctx->flags & MA_CRYPT_ENCRYPT)
        ma_crypt_pkcs7_pad((unsigned char *)src, &slen, AES_BLOCK_SIZE, 1);
      if (ctx->mode == MA_AES_ECB)
      {
        if (ctx->flags & MA_CRYPT_ENCRYPT)
          ctx->cipher.c->encrypt(ctx->ctx, slen, dst, src);
        else
          ctx->cipher.c->decrypt(ctx->ctx, slen, dst, src);
      } else {
        char *iiv;
        if (!(iiv= alloca(ctx->cipher.c->block_size)))
          return MA_CRYPT_ENOMEM;
        /* this is safe, we already checked iv_len during init */
        memcpy(iiv, ctx->iv, ctx->cipher.c->block_size);
        if (ctx->flags & MA_CRYPT_ENCRYPT)
          cbc_encrypt(ctx->ctx, ctx->cipher.c->encrypt, ctx->cipher.c->block_size,
                      iiv, slen, dst, src);
        else
          cbc_decrypt(ctx->ctx, ctx->cipher.c->decrypt, ctx->cipher.c->block_size,
                      iiv, slen, dst, src);

      }
      break;
    case MA_AES_GCM:
      if (ctx->flags & MA_CRYPT_ENCRYPT)
        ctx->cipher.a->encrypt(ctx->ctx, slen, dst, src);
      else
        ctx->cipher.a->decrypt(ctx->ctx, slen, dst, src);
      break;
    case MA_AES_CTR:
    {
      /* prevent reuse of modified iv */
      unsigned char *ctr= alloca(ctx->cipher.c->block_size);
      memcpy(ctr, ctx->iv, ctx->cipher.c->block_size);
      ctr_crypt(ctx->ctx, ctx->cipher.c->encrypt, ctx->cipher.c->block_size,
                ctr, slen, dst, src);
      break;    
    }
  }
  if (!rc)
    *dlen+= slen;
#elif HAVE_OPENSSL
  {
    unsigned int total= 0;
    *dlen= 0;
    if (ctx->mode == MA_AES_GCM)
    {
      if (ctx->flags & MA_CRYPT_DECRYPT)
      {
        slen-= AES_BLOCK_SIZE;
        if(!EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE,
                                (void*)(src + slen)))
          return MA_CRYPT_BADDATA;
      }
    }
    if (ctx->flags & MA_CRYPT_NOPAD)
    {
      if (slen % AES_BLOCK_SIZE)
        *dlen= ma_crypt_internal_pad(ctx, (char *)src, dst, &slen);
      if (slen < AES_BLOCK_SIZE)
        return rc;
    }
    total= *dlen;
    *dlen= 0;
    if (!EVP_CipherUpdate(ctx->ctx, dst, (int*)dlen, src, slen))
      return MA_CRYPT_BADDATA;
    *dlen+= total;
  }
#elif HAVE_SCHANNEL
#endif
  ctx->src= src;
  ctx->src_len= slen;

end:
  return rc;
}
/* }}} */

/* {{{ ma_crypt_finish */
int ma_crypt_finish(MA_CRYPT_CTX crypt_ctx,
                    unsigned char *dst,
                    unsigned int *dlen)
{
  _MA_CRYPT_CTX ctx= (_MA_CRYPT_CTX)crypt_ctx;
  int rc= MA_CRYPT_OK;

  if (!ctx)
    return MA_CRYPT_EINVCTX;

  *dlen= 0;
#ifdef HAVE_NETTLE
  switch (ctx->mode) {
  case MA_AES_ECB:
  case MA_AES_CBC:
    /* check if we need to remove padding at decryption */
    if ((ctx->flags & MA_CRYPT_DECRYPT) &&
        (!(ctx->flags & MA_CRYPT_NOPAD)) &&
         ctx->src_len >= AES_BLOCK_SIZE)
      ma_crypt_pkcs7_pad(dst, dlen, AES_BLOCK_SIZE, 0);
    break;
  case MA_AES_GCM:
    ctx->cipher.a->digest(ctx->ctx, ctx->cipher.a->block_size, dst);
    *dlen= (ctx->flags & MA_CRYPT_ENCRYPT) ? ctx->cipher.a->block_size :
                                            -ctx->cipher.a->block_size;
    break;
  }
#elif HAVE_OPENSSL
  if (!(ctx->flags & MA_CRYPT_NOPAD))
  {
    if (ctx->mode == MA_AES_GCM)
    {
      int fin;
      if (!EVP_CipherFinal_ex(ctx->ctx, dst, &fin))
        return MA_CRYPT_BADDATA;
      if (ctx->flags & MA_CRYPT_ENCRYPT)
      {
        if(!EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG, AES_BLOCK_SIZE, dst))
          return MA_CRYPT_BADDATA;
        *dlen= AES_BLOCK_SIZE;
      }
    } else {
      if (!EVP_CipherFinal_ex(ctx->ctx, dst, (int*)dlen))
        return 0;
    }
  }
#endif
  return rc;
}
/* }}} */

/* {{{ ma_crypt_free */
void ma_crypt_free(MA_CRYPT_CTX cipher_ctx)
{
  _MA_CRYPT_CTX ctx= (_MA_CRYPT_CTX)cipher_ctx;
  if (ctx)
  {
#ifdef HAVE_OPENSSL
    EVP_CIPHER_CTX_cleanup(ctx->ctx);
#elif HAVE_NETTLE
    free(ctx->ctx);
#endif
    free(ctx);
  }
}

int ma_crypt(enum ma_aes_mode mode,
             int flags,
             const unsigned char *src,
             unsigned int slen,
             unsigned char *dst,
             unsigned int *dlen,
             const unsigned char *key,
             unsigned int klen,
             const unsigned char *iv,
             unsigned int ivlen)
{
  void *ctx= ma_crypt_new();
  int res1= 0, res2= 0;
  unsigned int d1= 0, d2= 0;
  if ((res1= ma_crypt_init(ctx, mode, flags, key, klen, iv, ivlen)))
    return res1;
  res1= ma_crypt_update(ctx, src, slen, dst, &d1);
  res2= ma_crypt_finish(ctx, dst + d1, &d2);
  *dlen= d1 + d2;
  ma_crypt_free(ctx);
  return res1 ? res1 : res2;
}

int ma_crypt_random_bytes(unsigned char* buf, int num)
{
#ifdef HAVE_YASSL
  struct yarrow256_ctx ctx;
  yarrow256_init(&ctx, 0, NULL);
  yarrow256_random(&ctx, num, buf);
#endif
  return 0;
}
