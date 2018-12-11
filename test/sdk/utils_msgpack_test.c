#include "cmocka_init.h"
#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include <string.h>
#include <dslink/base64_url.h>
#include <stdio.h>
#include <printf.h>
#include <dslink/err.h>

//static
//void utils_str_replace_all_test(void **state) {
//    (void) state;
//
//    const char *str = "abc_abc_a";
//    char *rep = dslink_str_replace_all(str, "a", "123");
//    assert_non_null(rep);
//    assert_string_equal(rep, "123bc_123bc_123");
//    dslink_free(rep);
//
//    str = "abc_abc";
//    rep = dslink_str_replace_all(str, "abc", "1");
//    assert_non_null(rep);
//    assert_string_equal(rep, "1_1");
//    dslink_free(rep);
//}


// These adapted from mbedtls

static const struct {
    const char *type;

    const char *input;
    const char *output;
    int output_buffer_size;
    int expected_result;

} base64_tests[] = {
        {
            "encode_base64",
            "Man is distinguished, not only by his reason, but by this singular "
            "passion from other animals, which is a lust of the mind, that by a "
            "perseverance of delight in the continued and indefatigable generation "
            "of knowledge, exceeds the short vehemence of any carnal pleasure.",

            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieS"
            "B0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBh"
            "IGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodC"
            "BpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25v"
            "d2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbG"
            "Vhc3VyZS4=",
            512,
            0
        },
        {"encode_base64", "f", "Zg==", 5, 0 },
        {"encode_base64", "f", "Zg==", 4, DSLINK_BASE64_BUFFER_TOO_SMALL_ERR },
        {"encode_base64", "foo","Zm9v",5,0},
        {"encode_base64", "foo","Zm9v",4,DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"encode_base64", "foob","Zm9vYg==",9,0},
        {"encode_base64", "foob","Zm9vYg==",8,DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"encode_base64", "fooba","Zm9vYmE=",9,0},
        {"encode_base64", "fooba","Zm9vYmE=",8,DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"encode_base64", "foobar","Zm9vYmFy",9,0},
        {"encode_base64", "foobar","Zm9vYmFy",8,DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"encode_base64", "sdk-dslink-cpp","c2RrLWRzbGluay1jcHA=", 30, 0},
        {"encode_base64", "-cpp", "LWNwcA==", 20, 0},

        {
            "decode_base64",
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieS"
            "B0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBh"
            "IGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodC"
            "BpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25v"
            "d2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbG"
            "Vhc3VyZS4=",

            "Man is distinguished, not only by his reason, but by this singular "
            "passion from other animals, which is a lust of the mind, that by a "
            "perseverance of delight in the continued and indefatigable generation "
            "of knowledge, exceeds the short vehemence of any carnal pleasure.",

            512,
            0
        },

        {"decode_base64", "c2RrLWRzbGluay1jcHA=",    "sdk-dslink-cpp",   30, 0},
        {"decode_base64", "LWNwcA==",                "-cpp",             20, 0},
        {"decode_base64", "",            "",         10, 0},
        {"decode_base64", "Zg==",        "f",        10, 0},
        {"decode_base64", "Zm8=",        "fo",       10, 0},
        {"decode_base64", "Zm9v",        "foo",      10, 0},
        {"decode_base64", "Zm9v",        "foo",      1,  DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"decode_base64", "Zm9vYg==",    "foob",     10, 0},
        {"decode_base64", "Zm9vYmE=",    "fooba",    10, 0},
        {"decode_base64", "Zm9vYmFy",    "foobar",   10, 0},
        {"decode_base64", "Zm9vYmFy",    "foobar",   3,  DSLINK_BASE64_BUFFER_TOO_SMALL_ERR},
        {"decode_base64", "zm#=",        "",         10, DSLINK_BASE64_INVALID_CHARACTER_ERR},
        {"decode_base64", "zm===",       "",         10, DSLINK_BASE64_INVALID_CHARACTER_ERR},
        {"decode_base64", "zm=masd",     "",         10, DSLINK_BASE64_INVALID_CHARACTER_ERR},
        {"decode_base64", "zm masd",     "",         10, DSLINK_BASE64_INVALID_CHARACTER_ERR},

//TODO: Extend url
//        { "=123",       "",         10, 0},
//        { "123==",      "123",      10, 0},
//        { "1+2+3==",    "1-2-3",    10, 0},
//        { "1////23==",  "1____23",  10, 0},

};


static
void base64_test(void **state){
    (void) state;

    for(unsigned int i = 0; i < sizeof(base64_tests) / sizeof(base64_tests[0]); i++)
    {
        unsigned char* input = (unsigned char*)base64_tests[i].input;
        size_t input_size = strlen(base64_tests[i].input);

        int output_buffer_alloc_size = base64_tests[i].output_buffer_size;
        unsigned char* output_buffer = malloc(output_buffer_alloc_size);

        size_t olen;
        int output_return = 0;

        if(strcmp("encode_base64", base64_tests[i].type) == 0)
            output_return = dslink_base64_encode(output_buffer, output_buffer_alloc_size, &olen, input, input_size);
        else if(strcmp("decode_base64", base64_tests[i].type) == 0)
            output_return = dslink_base64_decode(output_buffer, output_buffer_alloc_size, &olen, input, input_size);
        else
            fail();

        assert_int_equal(output_return, base64_tests[i].expected_result);

        if(output_return != 0)
            goto continue_;
        assert_int_equal(olen, strlen(base64_tests[i].output));
        assert_memory_equal(base64_tests[i].output, output_buffer, olen);

        continue_:
        free(output_buffer);
    }
}


static
json_t* get_test_json()
{
    json_t *json = json_object();
    json_object_set_new(json, "str1", json_string_nocheck((char *) "Hello"));
    json_object_set_new(json, "boolean1", json_boolean(1));
    json_object_set_new(json, "str2", json_string_nocheck(""));
    json_object_set_new(json, "null1", json_null());
    json_object_set_new(json, "real1", json_real(3.221));
    json_object_set_new(json, "int1", json_integer(3));
    /* json_binary function is not implemented
    json_object_set_new(json, "binary1", json_binary("BINARRYYYYY12123123123123123"));
    json_object_set_new(json, "binary2", json_binary("BINARRYYYYY"));
    json_object_set_new(json, "binary3", json_binary("BINARY"));
    json_object_set_new(json, "binary4", json_binary("B"));
    json_object_set_new(json, "binary5", json_binary(""));
    */
    json_object_set_new(json, "array1", json_array());
    json_array_append(json_object_get(json,"array1"), json_string_nocheck("Hello_2"));
    json_array_append(json_object_get(json,"array1"), json_string_nocheck("msgpack32"));
    json_array_append(json_object_get(json,"array1"), json_boolean(0));
    json_array_append(json_object_get(json,"array1"), json_null());
    json_array_append(json_object_get(json,"array1"), json_real(3.221));
    json_array_append(json_object_get(json,"array1"), json_integer(3));
    /* json_binary function is not implemented
    json_array_append(json_object_get(json,"array1"), json_binary("BINARRYYYYY12123123123123123"));
    */

    return json;

}

#if 0
static
void msgpack_add_bin(msgpack_packer *pk, const char* str)
{
    msgpack_pack_bin(pk, strlen(str));
    msgpack_pack_bin_body(pk, str, strlen(str));
}
#endif

static
void msgpack_add_str(msgpack_packer *pk, const char* str)
{
    msgpack_pack_str(pk, strlen(str));
    msgpack_pack_str_body(pk, str, strlen(str));
}

static
msgpack_sbuffer* get_test_msgpack()
{
    /* msgpack::sbuffer is a simple buffer implementation. */
    msgpack_sbuffer* sbuf = malloc(sizeof(msgpack_sbuffer));
    msgpack_sbuffer_init(sbuf);

    /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
    msgpack_packer pk;
    msgpack_packer_init(&pk, sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pk, 7);

    msgpack_add_str(&pk, "str1");
    msgpack_add_str(&pk, "Hello");

    msgpack_add_str(&pk, "boolean1");
    msgpack_pack_true(&pk);

    msgpack_add_str(&pk, "str2");
    msgpack_add_str(&pk, "");

    msgpack_add_str(&pk, "null1");
    msgpack_pack_nil(&pk);

    msgpack_add_str(&pk, "real1");
    msgpack_pack_double(&pk, (double)3.221);

    msgpack_add_str(&pk, "int1");
    msgpack_pack_int64(&pk, 3);

    /* json_binary function is not implemented
    msgpack_add_str(&pk, "binary1");
    msgpack_add_bin(&pk, "BINARRYYYYY12123123123123123");

    msgpack_add_str(&pk, "binary2");
    msgpack_add_bin(&pk, "BINARRYYYYY");

    msgpack_add_str(&pk, "binary3");
    msgpack_add_bin(&pk, "BINARY");

    msgpack_add_str(&pk, "binary4");
    msgpack_add_bin(&pk, "B");

    msgpack_add_str(&pk, "binary5");
    msgpack_add_bin(&pk, "");
    */

    msgpack_add_str(&pk, "array1");
    msgpack_pack_array(&pk, 6);

    msgpack_add_str(&pk, "Hello_2");
    msgpack_add_str(&pk, "msgpack32");
    msgpack_pack_false(&pk);
    msgpack_pack_nil(&pk);
    msgpack_pack_double(&pk, 3.221);
    msgpack_pack_int64(&pk, 3);
    /* json_binary is not implemented
    msgpack_add_bin(&pk, "BINARRYYYYY12123123123123123");
    */

    //msgpack_sbuffer_destroy(&sbuf);

    return sbuf;
}


static
void assert_json_equal(const json_t *json_1, const json_t *json_2)
{
    char* js_dump_1 = json_dumps(json_1, JSON_SORT_KEYS);
    char* js_dump_2 = json_dumps(json_2, JSON_SORT_KEYS);

    assert_string_equal(js_dump_1, js_dump_2);

    free(js_dump_1);
    free(js_dump_2);
}

static
void json_msgpack_convert_test(void **state) {
    (void)state;

    // Base JSON
    json_t *json_1 = get_test_json();

    ///////////
    // TEST 1
    ///////////
    // JSON to MSGPACK
    msgpack_sbuffer* sbuffer = dslink_ws_json_to_msgpack(json_1);

    msgpack_zone mempool;
    msgpack_zone_init(&mempool, 2048);

    msgpack_object *deserialized = malloc(sizeof(msgpack_object));
    msgpack_unpack(sbuffer->data, sbuffer->size, NULL, &mempool, deserialized);

    // MSGPACK(from json) to JSON
    json_t *json_from_msg_from_json = dslink_ws_msgpack_to_json(deserialized);

    assert_json_equal(json_1, json_from_msg_from_json);

    ///////////
    // TEST 2
    ///////////
    msgpack_sbuffer* sbuffer2 = get_test_msgpack();

    msgpack_zone mempool2;
    msgpack_zone_init(&mempool2, 2048);

    msgpack_object *deserialized2 = malloc(sizeof(msgpack_object));
    msgpack_unpack(sbuffer2->data, sbuffer2->size, NULL, &mempool2, deserialized2);

    // MSGPACK to JSON
    json_t *json_from_msg = dslink_ws_msgpack_to_json(deserialized2);

    assert_json_equal(json_1, json_from_msg);


    json_decref(json_1);
    json_decref(json_from_msg_from_json);
    json_decref(json_from_msg);
}

int main() {
    const struct CMUnitTest tests[] = {
        //cmocka_unit_test(utils_str_replace_all_test),
        cmocka_unit_test(base64_test),
        cmocka_unit_test(json_msgpack_convert_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}


