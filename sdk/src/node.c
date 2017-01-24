#include <string.h>
#include <assert.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/base64.h>
#include "mbedtls/aes.h"
#include "dslink/mem/mem.h"
#include "dslink/ws.h"
#include "dslink/msg/list_response.h"
#include "dslink/msg/sub_response.h"
#include "dslink/utils.h"


DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile) {
    name = dslink_strdup(name);
    if (!name) {
        return NULL;
    }

    profile = dslink_strdup(profile);
    if (!profile) {
        dslink_free((void *) name);
        return NULL;
    }

    DSNode *node = dslink_calloc(1, sizeof(DSNode));
    if (!node) {
        goto cleanup;
    }

    node->parent = parent;
    node->name = name;
    node->profile = profile;
    node->data = NULL;

    if (parent) {
        size_t pathLen = strlen(parent->path);
        size_t nameLen = strlen(name);
        char *path = dslink_malloc(pathLen + nameLen + 2);
        node->path = path;
        if (!path) {
            goto cleanup;
        }
        memcpy(path, parent->path, pathLen);
        *(path + pathLen) = '/';
        memcpy(path + pathLen + 1, name, nameLen + 1);
    } else {
        node->path = dslink_calloc(1, sizeof(char));
        if (!node->path) {
            goto cleanup;
        }
    }

    return node;
cleanup:
    DSLINK_CHECKED_EXEC(dslink_free, (void *) name);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) profile);
    if (node) {
        DSLINK_CHECKED_EXEC(dslink_free, (void *) node->path);
        dslink_free(node);
    }
    return NULL;
}

int dslink_node_add_child(DSLink *link, DSNode *node) {
    assert(node);
    assert(node->parent);
    int ret = 0;
    if (!node->parent->children) {
        node->parent->children = dslink_malloc(sizeof(Map));
        if (!node->parent->children) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(node->parent->children,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal,
                            dslink_map_hash_key) != 0) {
            dslink_free(node->parent->children);
            node->parent->children = NULL;
            return DSLINK_ALLOC_ERR;
        }

    }

    assert(!dslink_map_contains(node->parent->children,
                                (void *) node->name));
    {
        if ((ret = dslink_map_set(node->parent->children,
                                  dslink_ref((char *) node->name, NULL),
                                  dslink_ref(node, NULL))) != 0) {
            return ret;
        }
    }

    if (!link->_ws) {
        return ret;
    }

    ref_t *refId = dslink_map_get(link->responder->list_subs,
                                  (void *) node->parent->path);
    if (!refId) {
        return ret;
    }
    uint32_t *id = refId->data;
    json_t *top = json_object();
    if (!top) {
        return ret;
    }
    json_t *resps = json_array();
    if (!resps) {
        goto cleanup;
    }
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    if (!resp) {
        goto cleanup;
    }
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream",
                                json_string_nocheck("open"));
    json_object_set_new_nocheck(resp, "rid", json_integer(*id));
    json_t *updates = json_array();
    if (!updates) {
        goto cleanup;
    }
    json_object_set_new_nocheck(resp, "updates", updates);
    json_t *update = json_array();
    if (!update) {
        goto cleanup;
    }
    json_array_append_new(updates, update);
    dslink_response_list_append_child(update, node);
    dslink_ws_send_obj(link->_ws, top);
cleanup:
    json_delete(top);
    return ret;
}

DSNode *dslink_node_get_path(DSNode *root, const char *path) {
    if (!root) {
        return NULL;
    } else if (strcmp(path, "/") == 0) {
        return root;
    } else if (*path == '/') {
        path++;
    }

    DSNode *node = root;
    const char *end = strchr(path, '/');
    if (end) {
        if (!node->children) {
            return NULL;
        }
        ref_t *ref = dslink_map_getl(node->children, (void *) path, end - path);
        if (!ref) {
            return NULL;
        }
        node = ref->data;
        return dslink_node_get_path(node, end);
    } else if (*path != '\0') {
        if (!node->children) {
            return NULL;
        }
        ref_t *ref = dslink_map_get(node->children, (void *) path);
        if (!ref) {
            return NULL;
        }
        return ref->data;
    }

    return node;
}

void dslink_node_tree_free_basic(DSNode *root) {
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->path);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->name);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->profile);
    DSLINK_CHECKED_EXEC(json_delete, root->value_timestamp);
    DSLINK_CHECKED_EXEC(json_delete, root->value);
    if (root->children) {
        dslink_map_foreach_nonext(root->children) {
            dslink_decref(entry->key);
            {
                DSNode *child = entry->value->data;
                child->parent = NULL;
                dslink_node_tree_free_basic(child);
                dslink_decref(entry->value);
            }
            MapEntry *tmp = entry->next;
            free(entry->node);
            free(entry);
            entry = tmp;
        }
        dslink_free(root->children->table);
        dslink_free(root->children);
    }

    if (root->data) {
    	dslink_decref(root->data);
    }

    if (root->meta_data) {
        dslink_map_free(root->meta_data);
        dslink_free(root->meta_data);
    }

    // TODO: remove node from open_streams, list_subs, and value_path_subs

    dslink_free(root);
}

void dslink_node_tree_free(DSLink *link, DSNode *root) {
    if (link && link->_ws && root->parent && root->parent->name) {
        ref_t *rrid = dslink_map_get(link->responder->list_subs,
                                       (void *) root->parent->path);
        if (!rrid) {
            goto cleanup;
        }
        uint32_t *rid = rrid->data;
        json_t *top = json_object();
        uint8_t send = 0;
        if (top) {
            json_t *resps = json_array();
            if (resps) {
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *resp = json_object();
                if (resp) {
                    json_array_append_new(resps, resp);
                    json_object_set_new_nocheck(resp, "rid",
                                                json_integer(*rid));
                    json_object_set_new_nocheck(resp, "stream",
                                                json_string_nocheck("open"));
                    json_t *updates = json_array();
                    if (updates) {
                        json_object_set_new_nocheck(resp, "updates", updates);
                        json_t *update = json_object();
                        if (update) {
                            json_array_append_new(updates, update);
                            json_object_set_new_nocheck(update,
                                                        "name",
                                                        json_string_nocheck(root->name));
                            json_object_set_new_nocheck(update,
                                                        "change",
                                                        json_string_nocheck("remove"));
                            send = 1;
                        }
                    }
                }
            }
            if (send) {
                dslink_ws_send_obj(link->_ws, top);
            }
            json_delete(top);
        }
    }
cleanup:
    dslink_node_tree_free_basic(root);
}
int dslink_node_set_meta_new(struct DSLink *link, DSNode *node, const char *name, json_t *value) {
    int result = dslink_node_set_meta(link, node, name, value);
    json_decref(value);
    return result;
}
int dslink_node_set_meta(DSLink *link, DSNode *node,
                         const char *name, json_t *value) {
    assert(node);
    assert(name);
    if (!node->meta_data) {
        if (!value) {
            return 0;
        }
        node->meta_data = dslink_malloc(sizeof(Map));
        if (!node->meta_data) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(node->meta_data,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal,
                            dslink_map_hash_key) != 0) {
            dslink_free(node->meta_data);
            node->meta_data = NULL;
            return DSLINK_ALLOC_ERR;
        }
    }

    int rem = 0;

    if (!value) {
        dslink_map_remove(node->meta_data, (char *) name);
        rem = 1;
    } else {
        name = dslink_strdup(name);
        if (!name) {
            return DSLINK_ALLOC_ERR;
        }

        if (dslink_map_set(node->meta_data, dslink_ref((char *) name, free),
                           dslink_ref(json_incref(value), (free_callback) json_decref)) != 0) {
            dslink_free((void *) name);
        }
    }

    if (link) {
        if (node->on_data_changed) {
            node->on_data_changed(link, node);
        }
    }
    if (!link->_ws) {
        return 0;
    }

    ref_t *refId = dslink_map_get(link->responder->list_subs,
                                  (void *) node->path);
    if (!refId) {
        return 0;
    }
    uint32_t *id = refId->data;
    json_t *top = json_object();
    if (!top) {
        return 1;
    }
    json_t *resps = json_array();
    if (!resps) {
        goto cleanup;
    }
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    if (!resp) {
        goto cleanup;
    }
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream",
                                json_string_nocheck("open"));
    json_object_set_new_nocheck(resp, "rid", json_integer(*id));
    json_t *updates = json_array();
    if (!updates) {
        goto cleanup;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    if (rem == 1) {
        json_t *update = json_object();
        if (!update) {
            goto cleanup;
        }
        json_object_set_new(update, "name", json_string_nocheck(name));
        json_object_set_new(update, "change", json_string_nocheck("remove"));
        json_array_append_new(updates, update);
    } else {
        json_t *update = json_array();
        if (!update) {
            goto cleanup;
        }
        json_array_append_new(update, json_string_nocheck(name));
        json_array_append(update, value);
        json_array_append_new(updates, update);
    }

    dslink_ws_send_obj(link->_ws, top);

    cleanup:
        json_delete(top);

    return 0;
}

json_t * dslink_node_get_meta(DSNode *node, const char *name) {
    if (!node->meta_data) {
        return NULL;
    }
    ref_t * ref = dslink_map_get(node->meta_data, (void*)name);
    if (ref) {
        return ref->data;
    }
    return NULL;
}

int dslink_node_set_value(struct DSLink *link, DSNode *node, json_t *value) {
    return dslink_node_update_value_new(link, node, value);
}

int dslink_node_update_value(struct DSLink *link, DSNode *node, json_t *value) {
    json_incref(value);
    int result = dslink_node_update_value_new(link, node, value);
    return result;
}

int dslink_node_update_value_new(struct DSLink *link, DSNode *node, json_t *value) {
    char ts[32];
    dslink_create_ts(ts, sizeof(ts));

    json_t *jsonTs = json_string_nocheck(ts);
    if (!jsonTs) {
        return DSLINK_ALLOC_ERR;
    }

    if (node->value_timestamp) {
        json_decref(node->value_timestamp);
    }

    if (node->value) {
        json_decref(node->value);
    }

    node->value_timestamp = jsonTs;
    node->value = value;

    if (link) {
        if (node->on_data_changed) {
            node->on_data_changed(link, node);
        }

        ref_t *sid = dslink_map_get(link->responder->value_path_subs,
                                    (void *) node->path);
        if (sid) {
            dslink_response_send_val(link, node, *((uint32_t *) sid->data));
        }
    }

    return 0;
}

json_t *dslink_node_serialize(DSLink *link, DSNode *node) {
    json_t * map = json_object();
    if (node->meta_data) {
        dslink_map_foreach(node->meta_data) {
            char *name = entry->key->data;
            json_t *value = entry->value->data;
            if (link && name[0] == '$' && name[1] == '$'
                && strcmp(name + strlen(name) - 8, "password") == 0
                && json_is_string(value) ) {
                // encrypt $$xxxpassword
                mbedtls_aes_context aes;

                unsigned char key[32];
                unsigned char iv[16] = {0};

                unsigned char input[128]= {0};
                unsigned char output[128];
                char base64[256] = {0};
                base64[0] = 0x1b;
                base64[1] = 'p';
                base64[2] = 'w';
                base64[3] = ':';

                size_t input_len = strlen(json_string_value(value));
                size_t base64_len = 0;

                memcpy(input, json_string_value(value), input_len);
                size_t output_len =  (input_len + 15) & 0xF0; // length needs to be 16x

                memcpy(key, link->key.d.p, 32);
                mbedtls_aes_setkey_enc( &aes, key, 256 );
                mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, output_len, iv, input, output);


                mbedtls_base64_encode((unsigned char*)base64+4,
                                      sizeof(base64)-4, &base64_len,
                                      output, output_len);

                json_object_set_new(map, name, json_string(base64));

            } else {
                json_object_set(map, name, entry->value->data);
            }

        }
    }
    if (node->value) {
        json_object_set(map, "?value", node->value);
    }
    return map;
}

void dslink_node_deserialize(DSLink *link, DSNode *node, json_t *data) {
    if (node->meta_data) {
        dslink_map_clear(node->meta_data);
    } else {
        node->meta_data = dslink_malloc(sizeof(Map));
        dslink_map_init(node->meta_data, dslink_map_str_cmp,
           dslink_map_str_key_len_cal, dslink_map_hash_key);
    }
    if (node->value) {
        json_decref(node->value);
        node->value = NULL;
    }

    const char *key;
    json_t *value;

    json_object_foreach(data, key, value) {
        if (strcmp(key,"?value") == 0) {
            dslink_node_update_value(NULL,node, value);
        } else {
            char *name = dslink_strdup(key);
            if (link && name[0] == '$' && name[1] == '$'
                && json_is_string(value) && memcmp("\x1bpw:", json_string_value(value), 4) == 0) {
                // decrypt password

                mbedtls_aes_context aes;

                unsigned char deckey[32];
                unsigned char iv[16] = {0};

                unsigned char input[128]= {0};
                unsigned char output[128] = {0};

                size_t input_len;

                const char *base64 = json_string_value(value);
                mbedtls_base64_decode(input,
                                      sizeof(input), &input_len,
                                      (const unsigned char *)base64+4, strlen(base64)-4);

                memcpy(deckey, link->key.d.p, 32);
                mbedtls_aes_setkey_dec( &aes, deckey, 256 );
                mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, input_len, iv, input, output);

                dslink_map_set(node->meta_data, dslink_ref(name, free),
                               dslink_ref(json_string((const char *)output), (free_callback) json_decref));
            } else {
                dslink_map_set(node->meta_data, dslink_ref(name, free),
                               dslink_ref(json_incref(value), (free_callback) json_decref));
            }
        }
    }
}

// Thread-safe API
int dslink_node_update_value_safe(struct DSLink *link, char* path, json_t *value,  void (*callback)(int, void*), void * callback_data) {

    DSLinkAsyncSetData *async_data = dslink_malloc(sizeof(DSLinkAsyncSetData));

    if (!async_data) {
        return DSLINK_ALLOC_ERR;
    }
    async_data->node_path = path;
    async_data->set_value = value;
    async_data->callback = callback;
    async_data->callback_data = callback_data;

    if(link) {
        link->async_set.data = (void*)async_data;
        uv_async_send(&link->async_set);
    }


    return 0;
}
int dslink_node_get_value_safe(struct DSLink *link, char* path,  void (*callback)(json_t *, void*), void * callback_data) {

    DSLinkAsyncGetData *async_data = dslink_malloc(sizeof(DSLinkAsyncGetData));

    if (!async_data) {
        return DSLINK_ALLOC_ERR;
    }
    async_data->node_path = path;
    async_data->callback = callback;
    async_data->callback_data = callback_data;

    if(link) {
        link->async_get.data = (void*)async_data;
        uv_async_send(&link->async_get);
    }

    return 0;
}
int dslink_run_safe(struct DSLink *link, void (*callback)(struct DSLink *link, void*), void * callback_data) {

    DSLinkAsyncRunData *async_data = dslink_malloc(sizeof(DSLinkAsyncRunData));

    if (!async_data) {
        return DSLINK_ALLOC_ERR;
    }
    async_data->callback = callback;
    async_data->callback_data = callback_data;

    if(link) {
        link->async_run.data = (void*)async_data;
        uv_async_send(&link->async_run);
    }

    return 0;
}
