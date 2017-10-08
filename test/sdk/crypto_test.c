#include "cmocka_init.h"

#include <stdint.h>
#include <dslink/crypto.h>
#include <dslink/err.h>


static
void crypto_ecdh_context_init_deinit_test(void **state){
    (void) state;

    dslink_ecdh_context* ctx = malloc(sizeof(dslink_ecdh_context));

    assert_function_success(dslink_crypto_ecdh_init_context(ctx));

    assert_non_null(ctx->grp);
    assert_non_null(ctx->eckey);
    assert_null(ctx->d);
    assert_null(ctx->Q);

    assert_function_success(dslink_crypto_ecdh_generate_keys(ctx));
    assert_non_null(ctx->d);
    assert_non_null(ctx->Q);

    assert_function_success(dslink_crypto_ecdh_deinit_context(ctx));

    free(ctx);
}

static
void crypto_set_keys_test(void **state){
    (void) state;

    for(int i = 0; i < 2; i++)
    {
        dslink_ecdh_context* ctx_1 = malloc(sizeof(dslink_ecdh_context));
        assert_function_success(dslink_crypto_ecdh_init_context(ctx_1));
        assert_function_success(dslink_crypto_ecdh_generate_keys(ctx_1));

        dslink_ecdh_context* ctx_2 = malloc(sizeof(dslink_ecdh_context));
        assert_function_success(dslink_crypto_ecdh_init_context(ctx_2));
        if(i == 0)
        {
            assert_function_success(dslink_crypto_ecdh_generate_keys(ctx_2));
            // Set Keys from other context and itself not matching public&private keys must be fail
            assert_int_equal(dslink_crypto_ecdh_set_keys(ctx_2, ctx_2->d, ctx_1->Q), DSLINK_CRYPT_KEY_SET_ERR);
        } else
        {
            assert_int_equal(dslink_crypto_ecdh_set_keys(ctx_2, NULL, NULL), DSLINK_CRYPT_KEY_SET_ERR);
        }

        // Set Keys from other context must be success
        assert_function_success(dslink_crypto_ecdh_set_keys(ctx_2, ctx_1->d, ctx_1->Q));

        assert_function_success(dslink_crypto_ecdh_deinit_context(ctx_1));
        free(ctx_1);

        assert_function_success(dslink_crypto_ecdh_deinit_context(ctx_2));
        free(ctx_2);
    }
}

static
void crypto_bignum_read_write_binary_test(void **state) {
    (void) state;

    dslink_ecdh_context* ctx = malloc(sizeof(dslink_ecdh_context));

    assert_function_success(dslink_crypto_ecdh_init_context(ctx));

    assert_function_success(dslink_crypto_ecdh_generate_keys(ctx));

    const DSLINK_CRYPTO_BIGNUM* bn = ctx->d;

    unsigned char insufficient_buffer[1];
    assert_int_equal(dslink_crypto_bn_write_binary(bn, insufficient_buffer, sizeof(insufficient_buffer)), -1);

    unsigned char buff[256];
    int buff_len = dslink_crypto_bn_write_binary(bn, buff, sizeof(buff));
    assert_int_not_equal(buff_len, -1);

    DSLINK_CRYPTO_BIGNUM* bn_2 = dslink_crypto_new_bn();
    assert_function_success(dslink_crypto_bn_read_binary(bn_2, buff, buff_len));

    assert_int_equal(dslink_crypto_compare_bn(bn, bn_2), 0);

    dslink_crypto_free_bn(bn_2);
    assert_function_success(dslink_crypto_ecdh_deinit_context(ctx));

    free(ctx);
}

static
void crypto_ecpoint_read_write_binary_test(void **state) {
    (void) state;

    dslink_ecdh_context* ctx = malloc(sizeof(dslink_ecdh_context));

    assert_function_success(dslink_crypto_ecdh_init_context(ctx));

    assert_function_success(dslink_crypto_ecdh_generate_keys(ctx));

    const EC_GROUP* ec_g = ctx->grp;
    const DSLINK_CRYPTO_EC_POINT* ec_p = ctx->Q;

    unsigned char insufficient_buffer[1];
    size_t olen;
    assert_int_equal(dslink_crypto_ecp_point_write_binary(ec_g, ec_p, &olen,
                                                          insufficient_buffer, sizeof(insufficient_buffer)), -1);

    unsigned char buff[256];
    int buff_len = dslink_crypto_ecp_point_write_binary(ec_g, ec_p, &olen, buff, sizeof(buff));
    assert_int_not_equal(buff_len, -1);

    DSLINK_CRYPTO_EC_POINT* ec_p_2 = dslink_crypto_new_ec_point(ec_g);
    assert_function_success(dslink_crypto_ecp_point_read_binary(ec_g, ec_p_2, buff, buff_len));

    assert_int_equal(dslink_crypto_compare_ec_point(ec_g, ec_p, ec_p_2, NULL), 0);

    dslink_crypto_free_ec_point(ec_p_2);

    assert_function_success(dslink_crypto_ecdh_deinit_context(ctx));

    free(ctx);
}

static
void crypto_calculate_secret_test(void **state){
    (void) state;

    dslink_ecdh_context* ctx_1 = malloc(sizeof(dslink_ecdh_context));
    assert_function_success(dslink_crypto_ecdh_init_context(ctx_1));
    assert_function_success(dslink_crypto_ecdh_generate_keys(ctx_1));

    dslink_ecdh_context* ctx_2 = malloc(sizeof(dslink_ecdh_context));
    assert_function_success(dslink_crypto_ecdh_init_context(ctx_2));

    size_t olen_err = 0;
    unsigned char secret_error[256];
    assert_int_equal(dslink_crypto_ecdh_calc_secret(ctx_2, &olen_err, secret_error, sizeof(secret_error)),
                     DSLINK_CRYPT_MISSING_KEYS_ERR);

    assert_function_success(dslink_crypto_ecdh_generate_keys(ctx_2));

    assert_int_equal(dslink_crypto_ecdh_calc_secret(ctx_2, &olen_err, secret_error, sizeof(secret_error)),
                     DSLINK_CRYPT_MISSING_KEYS_ERR);

    assert_function_success(dslink_crypto_ecdh_set_peer_public_key(ctx_1, ctx_2->Q));
    assert_function_success(dslink_crypto_ecdh_set_peer_public_key(ctx_2, ctx_1->Q));


    unsigned char secret_insufficient[1];
    assert_int_equal(dslink_crypto_ecdh_calc_secret(ctx_1, &olen_err, secret_insufficient, sizeof(secret_insufficient)),
                     DSLINK_CRYPT_INSUFFICIENT_BUFFER_ERR);

    size_t olen_1 = 0;
    unsigned char secret_1[256];
    assert_function_success(dslink_crypto_ecdh_calc_secret(ctx_1, &olen_1, secret_1, sizeof(secret_1)));

    size_t olen_2 = 0;
    unsigned char secret_2[256];
    assert_function_success(dslink_crypto_ecdh_calc_secret(ctx_2, &olen_2, secret_2, sizeof(secret_2)));

    // Check whether calculated secret is same?
    assert_int_equal(olen_1, olen_2);
    assert_memory_equal(secret_1, secret_2, olen_1);

    assert_function_success(dslink_crypto_ecdh_deinit_context(ctx_1));
    free(ctx_1);

    assert_function_success(dslink_crypto_ecdh_deinit_context(ctx_2));
    free(ctx_2);
}

static
void crypto_aes_test(void **state){
    (void) state;

    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";

    unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

    unsigned char cipher_text[128];
    int cipher_text_len;

    cipher_text_len = dslink_crypto_aes_encrypt(plaintext, strlen ((char *)plaintext),
                                                key, iv, cipher_text);
    assert_int_not_equal(cipher_text, -1);

    unsigned char decrypted_text[128];
    int decrypted_text_len;

    decrypted_text_len = dslink_crypto_aes_decrypt(cipher_text, cipher_text_len,
                                                   key, iv, decrypted_text);
    assert_int_not_equal(decrypted_text_len, -1);

    assert_int_equal(decrypted_text_len, strlen((char *)plaintext));
    assert_memory_equal(plaintext, decrypted_text, decrypted_text_len);
}

static
void crypto_random_test(void **state){
    (void) state;

    unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
    size_t buff_len = sizeof(plaintext);

    unsigned char *plaintext_rand = malloc(buff_len);
    memcpy(plaintext_rand, plaintext, buff_len);

    assert_memory_equal(plaintext, plaintext_rand, buff_len);
    dslink_crypto_random(plaintext_rand, buff_len);
    assert_memory_not_equal(plaintext, plaintext_rand, buff_len);

    unsigned char *plaintext_rand_2 = malloc(buff_len);
    memcpy(plaintext_rand_2, plaintext, buff_len);

    assert_memory_equal(plaintext, plaintext_rand_2, buff_len);
    dslink_crypto_random(plaintext_rand_2, buff_len);
    assert_memory_not_equal(plaintext, plaintext_rand_2, buff_len);

    // Check that whether it is not pseudo random
    assert_memory_not_equal(plaintext_rand, plaintext_rand_2, buff_len);

    free(plaintext_rand);
    free(plaintext_rand_2);
}

static
void crypto_set_fips_mode_on(void **state){
    (void) state;

    assert_int_equal(dslink_crypto_fips_mode_set(1), 1);
}

// adapted from https://github.com/cetic/6lbr/blob/master/examples/cc2538dk/crypto/sha256-test.c
static const struct {
    const char *data;
    uint8_t sha256[32];
    uint8_t sha1[20];
} vectors[] = {
        {
                "abc",
                {
                        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
                },
                {
                        0xa9, 0x99, 0x3e, 0x36, 0x47,
                        0x06, 0x81, 0x6a, 0xba, 0x3e,
                        0x25, 0x71, 0x78, 0x50, 0xc2,
                        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
                },
        },
        {
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                {
                        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
                },
                {
                        0x84, 0x98, 0x3e, 0x44, 0x1c,
                        0x3b, 0xd2, 0x6e, 0xba, 0xae,
                        0x4a, 0xa1, 0xf9, 0x51, 0x29,
                        0xe5, 0xe5, 0x46, 0x70, 0xf1,
                },
        },
        {
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcd"
                        "efghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",
                {
                        0x15, 0xd2, 0x3e, 0xea, 0x57, 0xb3, 0xd4, 0x61,
                        0xbf, 0x38, 0x91, 0x12, 0xab, 0x4c, 0x43, 0xce,
                        0x85, 0xe1, 0x68, 0x23, 0x8a, 0xaa, 0x54, 0x8e,
                        0xc8, 0x6f, 0x0c, 0x9d, 0x65, 0xf9, 0xb9, 0x23
                },
                {
                        0xf5, 0x3f, 0xcd, 0xe1, 0x58,
                        0x5a, 0x1e, 0x32, 0x30, 0x03,
                        0xd6, 0x24, 0x4b, 0xac, 0xb8,
                        0x41, 0x06, 0xdf, 0x02, 0x58,
                },
        },
        {
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcd"
                        "efghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
                {
                        0xf8, 0xa3, 0xf2, 0x26, 0xfc, 0x42, 0x10, 0xe9,
                        0x0d, 0x13, 0x0c, 0x7f, 0x41, 0xf2, 0xbe, 0x66,
                        0x45, 0x53, 0x85, 0xd2, 0x92, 0x0a, 0xda, 0x78,
                        0x15, 0xf8, 0xf7, 0x95, 0xd9, 0x44, 0x90, 0x5f
                },
                {
                        0x62, 0xe2, 0xd1, 0xa6, 0x17,
                        0x20, 0xb0, 0xcd, 0x63, 0xb5,
                        0x31, 0xaa, 0x59, 0xed, 0xc8,
                        0x9d, 0x42, 0x76, 0xcf, 0x98,
                }
        },
        {
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
                {
                        0x2f, 0xcd, 0x5a, 0x0d, 0x60, 0xe4, 0xc9, 0x41,
                        0x38, 0x1f, 0xcc, 0x4e, 0x00, 0xa4, 0xbf, 0x8b,
                        0xe4, 0x22, 0xc3, 0xdd, 0xfa, 0xfb, 0x93, 0xc8,
                        0x09, 0xe8, 0xd1, 0xe2, 0xbf, 0xff, 0xae, 0x8e
                },
                {
                        0x93, 0x24, 0x9d, 0x4c, 0x2f,
                        0x89, 0x03, 0xeb, 0xf4, 0x1a,
                        0xc3, 0x58, 0x47, 0x31, 0x48,
                        0xae, 0x6d, 0xdd, 0x70, 0x42,
                }
        },
        {
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",

                {
                        0x92, 0x90, 0x1c, 0x85, 0x82, 0xe3, 0x1c, 0x05,
                        0x69, 0xb5, 0x36, 0x26, 0x9c, 0xe2, 0x2c, 0xc8,
                        0x30, 0x8b, 0xa4, 0x17, 0xab, 0x36, 0xc1, 0xbb,
                        0xaf, 0x08, 0x4f, 0xf5, 0x8b, 0x18, 0xdc, 0x6a
                },
                {
                        0xd8, 0x40, 0x6e, 0x7b, 0x9f,
                        0xdf, 0x4f, 0x73, 0x57, 0xb2,
                        0x90, 0xe4, 0x4f, 0x9f, 0xdb,
                        0x13, 0xe1, 0x66, 0xe7, 0x06,
                }
        },
};


static
void crypto_sha256_test(void **state) {
    (void) state;

    for(unsigned int i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
    {
        unsigned char output[32];
        dslink_crypto_sha256((const unsigned char*)vectors[i].data, strlen(vectors[i].data), output);
        assert_memory_equal(vectors[i].sha256, output, 32);
    }
}

static
void crypto_sha1_test(void **state) {
    (void) state;

    for(unsigned int i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
    {
        unsigned char output[20];
        dslink_crypto_sha1((const unsigned char*)vectors[i].data, strlen(vectors[i].data), output);

        assert_memory_equal(vectors[i].sha1, output, 20);
    }
}


int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(crypto_ecdh_context_init_deinit_test),
            cmocka_unit_test(crypto_set_keys_test),
            cmocka_unit_test(crypto_bignum_read_write_binary_test),
            cmocka_unit_test(crypto_ecpoint_read_write_binary_test),
            cmocka_unit_test(crypto_calculate_secret_test),
            cmocka_unit_test(crypto_aes_test),
            cmocka_unit_test(crypto_random_test),
            cmocka_unit_test(crypto_set_fips_mode_on),
            cmocka_unit_test(crypto_sha256_test),
            cmocka_unit_test(crypto_sha1_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
