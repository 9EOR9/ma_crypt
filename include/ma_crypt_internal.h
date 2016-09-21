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

#ifdef HAVE_NETTLE
#include <nettle/aes.h>
#include <nettle/gcm.h>
#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/nettle-meta.h>
#include <nettle/yarrow.h>
#include <nettle/macros.h>

typedef struct st_nettle_ctx {
  union {
    const struct nettle_aead *a;       /* used by GCM only */
    const struct nettle_cipher *c;
  } cipher;
  void *ctx;                           /* nettle cipher context */
  enum ma_aes_mode mode;               /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  unsigned char pad_len;
  unsigned char src_len;
  const unsigned char *src;
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
} *_MA_CRYPT_CTX;
#elif HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

typedef struct st_openssl_ctx {
  EVP_CIPHER_CTX *ctx;
  enum ma_aes_mode mode;               /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  unsigned char pad_len;
  unsigned char src_len;
  const unsigned char *src;
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
} *_MA_CRYPT_CTX;
#endif

