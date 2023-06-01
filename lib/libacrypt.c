/****************************************************************************
 * @file  src/crypt.c
 *
 * @brief Implementation of libacrypt functions.
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "acrypt.h"

#define X(v) #v
#define VERSION(a,b,c) X(a) "." X(b) "." X(c)
#define LIBACRYPT_VERSION  VERSION(0,0,1)

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/**
 * @brief Encrypt an 'input' data of 'length' bytes with a predefined key.
 *
 * @param context current context state pointer
 * @param output pointer to output buffer
 * @param input pointer to input buffer
 * @param length size of input and output buffers
 *
 * @return Success (OK = 0) indicating success or negative POSIX errno.
 */

int crypt_buffer(struct crypt_context *context, uint8_t *output,
                 const uint8_t *input, unsigned int length)
{
  int i = 0;
  int cnt;
  uint8_t *k;
  struct crypt_context *ctx;

  /* Create a new context to make our code reentrant */

  ctx = malloc(sizeof(struct crypt_context));
  if (ctx == NULL)
    {
      fprintf(stderr, "Error: failed to allocate context struct\n");
      return -ENOMEM;
    }

  /* Allocate memory to the key */

  ctx->key = malloc(context->keylen);
  if (ctx->key == NULL)
    {
      fprintf(stderr, "Error: failed to allocate memory to the key\n");
      return -ENOMEM;
    }

  /* Copy the user key */

  memcpy(ctx->key, context->key, context->keylen);
  ctx->keylen = context->keylen;

  k = ctx->key;

  for (cnt = 0; cnt < length; cnt++)
    {
      k[i] = (k[i] + i) % 256;
      output[cnt] = input[cnt] ^ k[i];
#ifdef LIB_DEBUG
      printf("input[%d] => output[%d]\n", input[cnt], output[cnt]);
#endif
      i = ++i % ctx->keylen;
    }

  /* Free allocated memory */

  free(ctx->key);
  free(ctx);

  return 0;
}

/**
 * @brief Get the cryptolib version number
 *
 * @return The library version.
 */

const char *crypt_version(void)
{
  return LIBACRYPT_VERSION;
}

