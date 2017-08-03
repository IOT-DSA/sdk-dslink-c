
#include <dslink/crypto.h>

#define LOG_TAG "crypto"
#include <dslink/log.h>

#include <dslink/err.h>

///////////////////////////
/*
 * ECDH
 *
 *
 *
 */


int dslink_crypto_ecdh_init_context(dslink_ecdh_context* ctx)
{
    // in open ssl ECP_DP_SECP256R1 is NID_X9_62_prime256v1
    // look at https://www.ietf.org/rfc/rfc5480.txt
    // 2.1.1.1.  Named Curve
    ctx->grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ctx->grp)
        return DSLINK_CRYPT_KEY_INIT_ERR;

    ctx->eckey = EC_KEY_new();
    if (!ctx->eckey)
        return DSLINK_CRYPT_KEY_INIT_ERR;

    if(!EC_KEY_set_group(ctx->eckey, ctx->grp))
        return DSLINK_CRYPT_KEY_INIT_ERR;

    ctx->Qp = NULL;
    //ctx->z = NULL;

    // These are ghost
    ctx->d = NULL;
    ctx->Q = NULL;

    return 0;
}

int dslink_crypto_ecdh_deinit_context(dslink_ecdh_context *ctx)
{
    EC_KEY_free(ctx->eckey);
    EC_GROUP_free(ctx->grp);

    // DO NOT free ctx->d this is pointing data in eckey
    // DO NOT free ctx->Q this is pointing data in eckey

    if(ctx->Qp)
        EC_POINT_free(ctx->Qp);

//    if(ctx->z)
//        BN_free(ctx->z);

    ctx->eckey = NULL;
    ctx->grp = NULL;
    ctx->d = NULL;
    ctx->Q = NULL;
    ctx->Qp = NULL;
//    ctx->z = NULL;

    return 0;
}

int dslink_crypto_ecdh_generate_keys(dslink_ecdh_context *ctx)
{
    if (!EC_KEY_generate_key(ctx->eckey))
        goto error;

    ctx->d = EC_KEY_get0_private_key(ctx->eckey);
    if(!ctx->d) goto error;

    ctx->Q = EC_KEY_get0_public_key(ctx->eckey);
    if(!ctx->Q) goto error;

    return 1;

    error:
    return DSLINK_CRYPT_KEY_PAIR_GEN_ERR;
}

int dslink_crypto_ecdh_set_keys(dslink_ecdh_context *ctx,
                                BIGNUM* private_key,
                                EC_POINT* public_key)
{
    if(EC_KEY_set_private_key(ctx->eckey, private_key) != 1) goto error;
    if(EC_KEY_set_public_key(ctx->eckey, public_key) != 1) goto error;

    ctx->d = EC_KEY_get0_private_key(ctx->eckey);
    if(!ctx->d) goto error;

    ctx->Q = EC_KEY_get0_public_key(ctx->eckey);
    if(!ctx->Q) goto error;

    if(EC_KEY_check_key(ctx->eckey) != 1) goto error;

    return 0;

    error:
    return DSLINK_CRYPT_KEY_SET_ERR;
}


int dslink_crypto_bn_read_binary(BIGNUM *X, const unsigned char *buf, size_t buflen)
{
    if(!X)
        return DSLINK_CRYPT_INPUT_ERR;

    // It is actually write in X
    BIGNUM *just_for_test = BN_bin2bn(buf,buflen,X);

    if (!just_for_test)
        return DSLINK_CRYPT_KEY_DECODE_ERR;

    return 0;
}

int dslink_crypto_bn_write_binary( const BIGNUM *X, unsigned char *buf, size_t buflen )
{
    if(BN_num_bytes(X) > buflen) return -1;

    memset(buf, 0, buflen);

    int len = BN_bn2bin(X, buf);

    if(len == 0) return -1;

    return len;
}

int dslink_crypto_ecp_point_read_binary(const EC_GROUP *grp, EC_POINT *ec_point,
                                        const unsigned char *buf, size_t bufLen)
{
    if(!ec_point)
        return DSLINK_CRYPT_INPUT_ERR;

    BIGNUM *bn = BN_bin2bn(buf,bufLen,NULL);
    if (!bn)
        return DSLINK_CRYPT_KEY_DECODE_ERR;

    // It is actually write in ec_point
    EC_POINT* just_for_test = EC_POINT_bn2point(grp, bn, ec_point, NULL );
    BN_free(bn);

    if (!just_for_test)
        return DSLINK_CRYPT_KEY_DECODE_ERR;

    return 0;
}

int dslink_crypto_ecp_point_write_binary(const EC_GROUP *grp, const EC_POINT *ec_point,
                                         size_t *olen,
                                         unsigned char *buf, size_t buflen)
{
    BIGNUM *bn = EC_POINT_point2bn(grp, ec_point, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
    if (!bn)
        return -1;

    *olen = dslink_crypto_bn_write_binary(bn, buf, buflen);

    BN_free(bn);

    return *olen;
}

int dslink_crypto_ecdh_set_peer_public_key(dslink_ecdh_context* ctx,
                                           EC_POINT* peer_public_key)
{
    if(ctx->Qp)
        EC_POINT_free(ctx->Qp);

    ctx->Qp = EC_POINT_new(ctx->grp);
    EC_POINT_copy(ctx->Qp, peer_public_key);

    return 0;
}

int dslink_crypto_ecdh_calc_secret(dslink_ecdh_context *ctx, size_t *olen,
                                   unsigned char *buf, size_t blen)
{
    // CHECK
    if(!ctx->Qp || !ctx->eckey)
        return DSLINK_CRYPT_MISSING_KEYS_ERR;

    // calculate it and write into struct
    int secret_len = (EC_GROUP_get_degree(ctx->grp) + 7) / 8;

    if(secret_len > blen)
        return DSLINK_CRYPT_INSUFFICIENT_BUFFER_ERR;

    *olen = ECDH_compute_key(buf, secret_len, ctx->Qp, ctx->eckey, NULL);

//    if(ctx->z) BN_free(ctx->z);
//    ctx->z = BN_new();
//
//    dslink_crypto_bn_read_binary(ctx->z, buf, olen);

    return 0;
}


/////////////////////////////////////////////////////////////////////////////

int dslink_crypto_sha256( const unsigned char *input, size_t ilen, unsigned char output[32])
{
    int ret = 0;

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL) return DSLINK_ALLOC_ERR;

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) goto error;

    if(1 != EVP_DigestUpdate(mdctx, input, ilen)) goto error;

    int needed_size = EVP_MD_size(EVP_sha256());

    if(1 != EVP_DigestFinal_ex(mdctx, output, &needed_size)) goto error;

    exit:
    EVP_MD_CTX_destroy(mdctx);
    return ret;

    error:
    ret = DSLINK_CRYPT_SHA_ERR;
    goto exit;
}

int dslink_crypto_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
    int ret = 0;

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL) return DSLINK_ALLOC_ERR;

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) goto error;

    if(1 != EVP_DigestUpdate(mdctx, input, ilen)) goto error;

    int needed_size = EVP_MD_size(EVP_sha1());

    if(1 != EVP_DigestFinal_ex(mdctx, output, &needed_size)) goto error;

    exit:
    EVP_MD_CTX_destroy(mdctx);
    return ret;

    error:
    ret = DSLINK_CRYPT_SHA_ERR;
    goto exit;
}

/////////////////////////////////////////////////////////////////////////////

#include "openssl/rand.h"

static int IS_RAND_INITIALIZED = 0;
void dslink_crypto_random(unsigned char *buffer, size_t len)
{
    if(!IS_RAND_INITIALIZED) {
        RAND_poll();
        IS_RAND_INITIALIZED = 1;
    }

    RAND_bytes(buffer, len);
}

int dslink_crypto_fips_mode_set(int on)
{
    if (FIPS_mode_set(on) != 1) {
        log_fatal("Cannot change fips mode %s!\n", (on)?"on":"off");
        return 0;
    }

    log_info("Fips mode %s!\n", (on)?"on":"off");

    return 1;
}


///////////////////////////
/*
 * AES
 * adapted from : https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 *
 *
 */
int dslink_crypto_aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                              unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return DSLINK_ALLOC_ERR;

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto error;

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto error;

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto error;

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Clear other non sense data.
    for(int i = plaintext_len; i < ciphertext_len; i++ ) plaintext[i] = NULL;

    return plaintext_len;

    error:
    EVP_CIPHER_CTX_free(ctx);
    return DSLINK_CRYPT_DECRYPT_ERR;

}


int dslink_crypto_aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                              unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return DSLINK_ALLOC_ERR;

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto error;

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto error;

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto error;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

    error:
    EVP_CIPHER_CTX_free(ctx);
    return DSLINK_CRYPT_ENCRYPT_ERR;
}

