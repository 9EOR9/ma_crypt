#include <ma_crypt.h>
#include <ma_hash.h>
#include <stdio.h>
#include <tap.h>

typedef struct t_string {
  char *str;
  unsigned int len;
} HEX_STR;

struct st_crypt_test {
  const char *name;
  enum ma_aes_mode mode;
  int flags;
  char *key;
  char *cleartext;
  char *ciphertext;
  char *md5;
  char *iv;
};

#define t_str_free(a)\
free((a)->str);\
free((a));

struct t_string *hex2str(char *hex)
{
  char *end;
  struct t_string *t_str= calloc(1, sizeof(struct t_string));
  unsigned int u, len= 0;
  char *p;

  if (hex == NULL)
    return t_str;

  if (!(end = strchr(hex, 13)) &&
      !(end = strchr(hex, 10)))
    end= hex + strlen(hex);
  
  t_str->str= malloc(strlen(hex) / 2 + 16);

  while (hex < end && sscanf(hex, "%2x", &u))
  {
    hex+= 2;
    t_str->str[len++]= (unsigned char)u;
  }
  t_str->len= len;
  return t_str;
}

int run_cipher_test(struct st_crypt_test test)
{
  char dst[1000], decrypted[1000];
  int i;
  int rc= 0;
  unsigned int dlen, decrypted_len;
  struct t_string *key= hex2str(test.key);
  struct t_string *iv= hex2str(test.iv);
  struct t_string *src= hex2str(test.cleartext);
  struct t_string *exp= hex2str(test.ciphertext);
  struct t_string *md5= hex2str(test.md5);

   ma_crypt(test.mode, MA_CRYPT_ENCRYPT | test.flags,
            src->str, src->len,
            dst, &dlen, key->str, key->len,
            iv->str, iv->len);
  if (exp->len)
  {
    if (dlen != exp->len)
    {
      diag("dlen: %d exp.len: %d", dlen, exp->len);
      diag("wrong length");
      goto end;
    }
    if (memcmp(dst, exp->str, dlen) != 0)
    {
      diag("wrong result");
      goto end;
    }
  }
  if (md5->len)
  {
    unsigned char md5_str[16];
    ma_hash(MA_HASH_MD5, md5_str, dst, dlen);
    if (memcmp(md5->str, md5_str, 16) != 0)
    {
      diag("md5 error\n");
      diag("src_len: %d  dest_len: %d", src->len, dlen);
      goto end;
    }
  }
  ma_crypt(test.mode, MA_CRYPT_DECRYPT | test.flags,
           dst, dlen,
           decrypted, &decrypted_len, key->str, key->len,
           iv->str, iv->len);

  if (memcmp(decrypted, src->str, decrypted_len) != 0)
  {
    diag("decrypt failed\n");
    diag("src_len: %d decrypted len: %d\n", dlen, decrypted_len);
    diag("%s", src->str);
    diag("%s", decrypted);
    goto end;
  }

  rc= 1;
end:
  t_str_free(key);
  t_str_free(iv);
  t_str_free(src);
  t_str_free(exp);
  t_str_free(md5);
  return rc;
}

int run_test_file(const char *filename)
{
  FILE *fp;
  struct st_crypt_test test;
  char line[1024];
  char *p, *key, *val;
  char test_name[100];
  int test_nr= 0;
  char *name= NULL;

  if (!(fp= fopen(filename, "r")))
  {
    printf("File not found\n");
    return 1;
  }
  memset(&test, 0, sizeof(struct st_crypt_test));
  test.flags= MA_CRYPT_NOPAD;
  while (fgets(line, 1024, fp))
  {

    /* remove trailing bullshit */
    if ((p= strchr(line, 13)) ||
        (p= strchr(line, 10)))
      *p= 0;

    if ((p= strchr(line, '=')))
    {
      *p= 0;
      key= line;
      val= p+1;

      if (strcmp(key, "TESTS") == 0)
        plan(atoi(val));
      if (strcmp(key, "MODE") == 0)
      {
        if (strcmp(val, "MA_AES_ECB") == 0)
          test.mode= MA_AES_ECB;
        else if (strcmp(val, "MA_AES_CBC") == 0)
          test.mode= MA_AES_CBC;
        else if (strcmp(val, "MA_AES_GCM") == 0)
          test.mode= MA_AES_GCM;
        else if (strcmp(val, "MA_AES_CTR") == 0)
          test.mode= MA_AES_CTR;
      }
      else if (strcmp(key, "NAME") == 0)
      {
        free(name);
        test_nr= 0;
        name= strdup(val);
      }
      else if (strcmp(key, "PT") == 0)
        test.cleartext= strdup(val);
      else if (strcmp(key, "KEY") == 0)
        test.key= strdup(val);
      else if (strcmp(key, "MD5") == 0)
        test.md5= strdup(val);
      else if (strcmp(key, "IV") == 0)
        test.iv= strdup(val);
      else if (strcmp(key, "CT") == 0)
        test.ciphertext= strdup(val);
      else if (strcmp(key, "PAD") == 0)
      {
        if (strcmp(val, "0") == 0)
          test.flags= MA_CRYPT_NOPAD;
        else
          test.flags= 0;
      }
      if (test.cleartext &&
          test.key &&
          (test.ciphertext || test.md5))
      {
        test_nr++;
        sprintf(test_name, "%s %d", name, test_nr);
        test.name= test_name;
        ok(run_cipher_test(test), test_name);
        free(test.ciphertext);
        free(test.iv);
        free(test.md5);
        free(test.key);
        free(test.cleartext);
        test.ciphertext= test.iv= test.md5= test.key= test.cleartext= 0;
      }
    }
  }
  if (name)
    free(name);
  fclose(fp);
  done_testing();
}

