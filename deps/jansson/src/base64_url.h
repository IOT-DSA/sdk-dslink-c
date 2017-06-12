#ifndef BASE64_URL_H
#define BASE64_URL_H

#include <stddef.h>

#define JSON_ERR_BASE64_BUFFER_TOO_SMALL               -0x002A  /**< Output buffer too small. */
#define JSON_ERR_BASE64_INVALID_CHARACTER              -0x002C  /**< Invalid character in input. */

/**
 * Encodes a string into base64 format without padding
 */
int json_base64_url_encode(unsigned char *dst,
                             size_t dLen,
                             size_t *olen,
                             const unsigned char *src,
                             size_t sLen);

/**
 * Decodes a base64 string
 */
int json_base64_url_decode(unsigned char *dst,
                             size_t dLen,
                             size_t *oLen,
                             const unsigned char *src,
                             size_t sLen);

#endif //BASE64_URL_H
