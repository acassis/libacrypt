/****************************************************************************
 * @file  src/crypt.h
 * 
 * @brief Definition of libacrypt functions.
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @struct crypt_context
 *  @brief This structure saves the current context
 *  @var crypt_context::key
 *  Member 'key' contains a pointer to user supplied key
 *  @var crypt_context::keylen 
 *  Member 'keylen' contains the length of user key.
 */
struct crypt_context
{
  uint8_t *key;    /* Pointer to user supplied key */
  int      keylen; /* Length of user key */
};

/**
 * @brief Encrypts an input string of size length with a predefined key.
 *
 * @param context current context state pointer
 * @param output pointer to output buffer
 * @param input pointer to input buffer
 * @param length size of input and output buffers
 *
 * @return 0 indicating success or negative POSIX errno.
 *
 */

int crypt_buffer(struct crypt_context *context, uint8_t *output,
                 const uint8_t *input, unsigned length);

/**
 * @brief Get the cryptolib version number
 *
 * @return The string version to library version.
 *
 */

char* crypt_version(void);

#ifdef __cplusplus
}
#endif

