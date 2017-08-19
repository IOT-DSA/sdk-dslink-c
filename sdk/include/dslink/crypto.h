
#ifndef SDK_DSLINK_C_CRYPTO_H
#define SDK_DSLINK_C_CRYPTO_H

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
/*NID_X9_62_prime256v1*/
#include <openssl/evp.h>

typedef struct{
    EC_GROUP *grp;
    EC_KEY *eckey;

    EC_POINT *Qp;                /*!<  peer's public value (public key)              */
//    BIGNUM *z;                   /*!<  shared secret                                 */
//
//    // These are just ptr in eckey DO NOT FREE THEM
    const BIGNUM *d;                   /*!<  our secret value (private key)                */
    const EC_POINT *Q;                 /*!<  our public value (public key)                 */

}dslink_ecdh_context;

//////////////////////////////////////////////////////////////////////////////////////////

int dslink_crypto_ecdh_init_context(dslink_ecdh_context* ctx);
int dslink_crypto_ecdh_deinit_context(dslink_ecdh_context *ctx);
int dslink_crypto_ecdh_generate_keys(dslink_ecdh_context *ctx);
int dslink_crypto_ecdh_set_keys(dslink_ecdh_context *ctx,
                                BIGNUM* private_key,
                                EC_POINT* public_key);

int dslink_crypto_bn_read_binary(BIGNUM *X, const unsigned char *buf, size_t buflen);
int dslink_crypto_bn_write_binary(const BIGNUM *X, unsigned char *buf, size_t buflen);


int dslink_crypto_ecp_point_read_binary(const EC_GROUP *grp, EC_POINT *ec_point,
                                        const unsigned char *buf, size_t bufLen);
int dslink_crypto_ecp_point_write_binary(const EC_GROUP *grp, const EC_POINT *ec_point,
                                         size_t *olen,
                                         unsigned char *buf, size_t buflen);

int dslink_crypto_ecdh_set_peer_public_key(dslink_ecdh_context* ctx,
                                           EC_POINT* peer_public_key);
int dslink_crypto_ecdh_calc_secret(dslink_ecdh_context *ctx, size_t *olen,
                                   unsigned char *buf, size_t blen);

//////////////////////////////////////////////////////////////////////////////////////////

int dslink_crypto_sha256( const unsigned char *input, size_t ilen, unsigned char output[32] );

int dslink_crypto_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] );

//////////////////////////////////////////////////////////////////////////////////////////

void dslink_crypto_random(unsigned char *buffer, size_t len);

//////////////////////////////////////////////////////////////////////////////////////////

int dslink_crypto_aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                              unsigned char *iv, unsigned char *plaintext);

int dslink_crypto_aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                              unsigned char *iv, unsigned char *ciphertext);

int dslink_crypto_fips_mode_set(int on);

#endif //SDK_DSLINK_C_CRYPTO_H
