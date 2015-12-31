#ifndef SDK_DSLINK_C_BASE64_URL_H
#define SDK_DSLINK_C_BASE64_URL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * Encodes a string into base64 format without padding
 */
int dslink_base64_url_encode(unsigned char *dst,
                             size_t dLen,
                             size_t *olen,
                             const unsigned char *src,
                             size_t sLen);

/**
 * Decodes a base64 string
 */
int dslink_base64_url_decode(unsigned char *dst,
                             size_t dLen,
                             size_t *oLen,
                             const unsigned char *src,
                             size_t sLen);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_BASE64_URL_H
