# ma_crypt
MariaDB crypto wrapper library

Crypto libraries supported:
* OpenSSL (min. required version 1.0.1)
* Nettle (used by GnuTLS)
* BCrypt (Windows native Crypto next generation)

Supported block ciphers and sizes
* AES-128
* AES-192
* AES-256

Supported block cipher modes of operation
* ECB (electronic codebook)
* CBC (cipher block chaining)
* GCM (galois/counter mode)
* CTR (counter)

Supported hash algorithms
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512
