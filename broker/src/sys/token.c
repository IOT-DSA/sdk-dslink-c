#include <string.h>

#include <broker/sys/token.h>
#include <broker/utils.h>
#include <broker/msg/msg_invoke.h>
#include <broker/net/ws.h>
#include <broker/config.h>
#include <broker/broker.h>
#include <broker/stream.h>

#include <dslink/base64_url.h>
#include <dslink/utils.h>
#include <dslink/crypto.h>


#define LOG_TAG "token"
#include <dslink/log.h>

static
BrokerNode *tokenRootNode;

static
unsigned char get_random_byte() {
    // reuse the entropy
    static unsigned char buffer[32];
    static int buffer_pos = 0;

    if (buffer_pos >= (int)sizeof(buffer))
        buffer_pos = 0;

    if (buffer_pos == 0)
        dslink_crypto_random(buffer, sizeof(buffer));

    return (unsigned char)(buffer[buffer_pos] & 0x7F);
}
static
unsigned char get_random_char() {
    while(1) {
        unsigned char n = (unsigned char)(get_random_byte() & 0x7F);
        if ((n >= '0' && n <= '9') ||
            (n >= 'A' && n <= 'Z') ||
            (n >= 'a' && n <= 'z')) {
            return n;
        }
    }
}

static
void clear_managed_link(const char * name){
    Map* map = dslink_calloc(1, sizeof(Map));

    Broker *broker = mainLoop->data;

    dslink_map_init(map, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);

    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
    json_t *updates = json_array();

    List nodeToDelete;
    list_init(&nodeToDelete);

    json_t *update_cache = NULL;
    if (broker->downstream->list_stream) {
        update_cache = broker->downstream->list_stream->updates_cache;
    }

    int foundlink = 0;
    dslink_map_foreach(broker->downstream->children) {
        DownstreamNode *dsn = (DownstreamNode *) entry->value->data;
        json_t *tokenjson = json_object_get(dsn->meta, "$$token");
        const char * tokenstr = json_string_value(tokenjson);
        if (tokenstr && strcmp(tokenstr, name) == 0) {
            if (dsn->link) {
                broker_close_link(dsn->link);
                dsn->link = NULL;
            }
            dslink_list_insert(&nodeToDelete, dsn);
            json_t *update = json_object();
            json_object_set_new_nocheck(update, "name", json_string_nocheck(dsn->name));
            json_object_set_new_nocheck(update, "change",
                                        json_string_nocheck("remove"));
            json_array_append_new(updates, update);
            if (update_cache) {
                json_object_del(update_cache, dsn->name);
            }
            foundlink++;
        } else {
            dslink_map_set(
                    map,
                    dslink_str_ref(dsn->name), dslink_ref(dsn, NULL));
        }
    }
    if (foundlink) {
        json_object_set_new_nocheck(resp, "updates", updates);

        if (broker->downstream->list_stream) {
            dslink_map_foreach(&broker->downstream->list_stream->requester_links) {
                uint32_t *rid = entry->value->data;
                json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
                broker_ws_send_obj(entry->key->data, top);
            }
        }
        dslink_map_clear(broker->downstream->children);
        Map* omap = broker->downstream->children;

        broker->downstream->children = map;

        dslink_map_free(omap);
        dslink_list_foreach(&nodeToDelete) {
            ListNode *lnode =  (ListNode *)node;
            DownstreamNode *dsn = lnode->value;
            // set to NULL to skip the removing from parent part
            dsn->parent = NULL;
            broker_node_free((BrokerNode*)dsn);
        }
        broker_downstream_nodes_changed(mainLoop->data);
    } else {
        dslink_map_free(map);
    }

    dslink_list_free_all_nodes(&nodeToDelete);
    json_decref(top);
}
static
void delete_token_invoke(RemoteDSLink *link,
                         BrokerNode *node,
                         json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    broker_utils_send_closed_resp(link, req, NULL);

    BrokerNode *parentNode = node->parent;

    if (json_is_true(json_object_get(parentNode->meta, "$$managed"))) {
        clear_managed_link(parentNode->name);
    }
    char tmp[256];
    int len = snprintf(tmp, sizeof(tmp) - 1, "token/%s", parentNode->name);
    tmp[len] = '\0';

    uv_fs_t unlink_req;
    uv_fs_unlink(NULL, &unlink_req, tmp, NULL);

    broker_node_free(parentNode);
}

static
void save_token_node(BrokerNode *node) {
    char tmp[128];
    const char *base = broker_get_storage_path("token");

    sprintf(tmp, "%s/%s", base, node->name);

    dslink_free((void *) base);

    json_dump_file(node->meta, tmp, 0);
}

static
BrokerNode *load_token_node(const char* tokenName, json_t* data) {
    BrokerNode *tokenNode = broker_node_create(tokenName, "node");
    if (!tokenNode) {
        return NULL;
    }
    const char* key;
    json_t* value;
    json_object_foreach(data, key, value) {
        json_object_set_nocheck(tokenNode->meta, key, value);
    }

    broker_node_add(tokenRootNode, tokenNode);

    BrokerNode *deleteAction = broker_node_create("delete", "node");
    json_object_set_new_nocheck(deleteAction->meta, "$invokable", json_string_nocheck("config"));
    broker_node_add(tokenNode, deleteAction);

    deleteAction->on_invoke = delete_token_invoke;
    return tokenNode;
}

static
void add_token_invoke(RemoteDSLink *link,
                  BrokerNode *node,
                  json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    (void) node;

    json_t *params = NULL;
    if (req) {
        params = json_object_get(req, "params");
    }
    if (params && !json_is_object(params)) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return;
    }

    char tokenName[49] = {0};
    do {
        // find a token name that's not in the parent node's children
        for (size_t i = 0; i < 16; ++i) {
            tokenName[i] = get_random_char();
        }
    } while (dslink_map_contains(tokenRootNode->children, tokenName));

    BrokerNode *tokenNode = broker_node_create(tokenName, "node");
    if (!tokenNode) {
        return;
    }

    // generate full token
    for (size_t i = 16; i < 48; ++i) {
        tokenName[i] = get_random_char();
    }

    if (json_object_set_new_nocheck(tokenNode->meta, "$$token", json_string_nocheck(tokenName)) != 0) {
        goto fail;
    }

    if (params) {
        json_t* timeRange = json_object_get(params , "TimeRange");
        if (json_is_string(timeRange) && *json_string_value(timeRange) != '\0') {
            json_object_set_nocheck(tokenNode->meta, "$$timeRange", timeRange);
        }

        json_t* count = json_object_get(params , "Count");
        if (json_is_number(count)) {
            if (json_is_integer(count)) {
                json_object_set_nocheck(tokenNode->meta, "$$count", count);
            } else {
                double vd = json_number_value(count);
                int64_t vi = (int64_t)vd;
                json_object_set_new_nocheck(tokenNode->meta, "$$count", json_integer(vi));
            }

        }

        json_t* managed = json_object_get(params , "Managed");
        if (json_is_boolean(managed)) {
            json_object_set_nocheck(tokenNode->meta, "$$managed", managed);
        }

        json_t* group = json_object_get(params , "Group");
        if (json_is_string(group) && *json_string_value(group) != '\0') {
            json_object_set_nocheck(tokenNode->meta, "$$group", group);
        }
    }

    if (broker_node_add(tokenRootNode, tokenNode) != 0) {
        goto fail;
    }

    BrokerNode *deleteAction = broker_node_create("delete", "node");
    json_object_set_new_nocheck(deleteAction->meta, "$invokable", json_string_nocheck("config"));
    broker_node_add(tokenNode, deleteAction);

    deleteAction->on_invoke = delete_token_invoke;

    log_info("Token added `%s`\n", tokenName);
    save_token_node(tokenNode);

    if (link && req) {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_t *rid = json_object_get(req, "rid");
        json_object_set_nocheck(resp, "rid", rid);
        json_object_set_new_nocheck(resp, "stream",
                                    json_string_nocheck("closed"));

        json_t *updates = json_array();
        json_t *row = json_array();
        json_array_append_new(updates, row);
        json_array_append_new(row, json_string_nocheck(tokenName));
        json_object_set_new_nocheck(resp, "updates", updates);

        broker_ws_send_obj(link, top);
        json_decref(top);
    }

    return;
fail:
    broker_node_free(tokenNode);
}

BrokerNode *get_token_node(const char *hashedToken, const char *dsId) {
    char tokenId[17] = {0};
    char tokenHash[64] = {0};
    memcpy(tokenId, hashedToken, 16);
    strncpy(tokenHash, hashedToken+16, 64);

    ref_t *ref = dslink_map_get(tokenRootNode->children, tokenId);
    if (!ref) {
        return NULL;
    }

    BrokerNode* node = ref->data;

    json_t *countJson = json_object_get(node->meta, "$$count");
    if (json_is_integer(countJson) && json_integer_value(countJson) <= 0) {
        return NULL;
    }

    json_t* tokenJson = json_object_get(node->meta, "$$token");
    if (!json_is_string(tokenJson)) {
        return NULL;
    }
    const char *token = json_string_value(tokenJson);

    uv_fs_t stat_req;

    char tokenPath[256];

    {
        int len = snprintf(tokenPath, sizeof(tokenPath) - 1, "token/%s", tokenId);
        tokenPath[len] = '\0';
    }

    int res = uv_fs_stat(NULL, &stat_req, tokenPath, NULL);

    if (res < 0) {
        dslink_map_remove(tokenRootNode->children, tokenId);
        return NULL;
    }

    unsigned char hashBinary[40];
    size_t outlen;
    dslink_base64_url_decode(hashBinary,40, &outlen, (unsigned char*)tokenHash, strlen(tokenHash));

    size_t id_len = strlen(dsId) ;
    char *in = dslink_malloc(id_len + 49);
    memcpy(in, dsId, id_len);
    memcpy(in + id_len, token, 48);
    *(in + id_len + 48) = '\0';

    unsigned char auth[32];
    dslink_crypto_sha256((unsigned char *) in, id_len + 48, auth);
    dslink_free(in);

    if (memcmp(auth, hashBinary, 32) == 0) {
        return node;
    }

    return NULL;
}

void token_used(BrokerNode *tokenNode) {
    json_t *countJson = json_object_get(tokenNode->meta, "$$count");
    if (json_is_integer(countJson)) {
        int64_t count = json_integer_value(countJson);
        if (count > 0) {
            count--;
            json_object_set_new_nocheck(tokenNode->meta, "$$count", json_integer(count));
            save_token_node(tokenNode);
        }
    }
}

static
void append_file_token(json_t *json) {
    if(json_is_object(json)) {
        json_t* token = json_object_get(json, "$$token");
        if (json_is_string(token)) {
            const char *tokenstr = json_string_value(token);
            char name[17];
            memcpy(name, tokenstr, 16);
            name[16] = 0;
            BrokerNode * tokenNode = load_token_node(name, json);
            if (tokenNode) {
                save_token_node(tokenNode);
            }

        }
    }
}

static
void parse_new_token_json(const char* path, json_t* json) {
    if (json_is_array(json)) {
        size_t index;
        json_t *value;
        json_array_foreach(json, index, value) {
            append_file_token(value);
        }
    } else {
        append_file_token(json);
    }
    uv_fs_t unlink_req;
    uv_fs_unlink(NULL, &unlink_req, path, NULL);
}

static
void new_file_token_changed(uv_fs_poll_t* handle,
                      int status,
                      const uv_stat_t* prev,
                      const uv_stat_t* curr) {
    (void)prev;
    (void)curr;
    if (status == 0) {
        json_error_t err;
        json_t *val = json_load_file(handle->data, 0 , &err);
        parse_new_token_json(handle->data, val);
    }

}

static uv_fs_poll_t newTokenFileHandler;

static
int load_tokens() {
    uv_fs_t dir;

    const char *base = broker_get_storage_path("token");

    uv_fs_mkdir(NULL, &dir, base, 0770, NULL);

    if (uv_fs_scandir(NULL, &dir, base, 0, NULL) < 0) {
        return 0;
    }

    uv_dirent_t d;
    while (uv_fs_scandir_next(&dir, &d) != UV_EOF) {
        if (d.type != UV_DIRENT_FILE) {
            continue;
        }

        char tmp[256];
        int len = snprintf(tmp, sizeof(tmp) - 1, "%s/%s", base, d.name);
        tmp[len] = '\0';

        json_error_t err;
        json_t *val = json_load_file(tmp, 0 , &err);
        if (val) {
            if (strlen(d.name) == 16) {
                load_token_node(d.name, val);
            } else if (strcmp(d.name, "append") == 0) {
                // find token name from json
                parse_new_token_json(tmp, val);
            }

            json_decref(val);
        }
    }

    char *newTokenPath = (char*)broker_pathcat(base, "append");
    uv_fs_poll_init(mainLoop, &newTokenFileHandler);
    uv_fs_poll_start(&newTokenFileHandler, new_file_token_changed, newTokenPath, 1000);
    newTokenFileHandler.data = newTokenPath;

    dslink_free((void *) base);


    return 0;
}

int init_tokens(BrokerNode *sysNode) {
    BrokerNode *tokensNode = broker_node_create("tokens", "node");
    if (!tokensNode) {
        return 1;
    }

    if (broker_node_add(sysNode, tokensNode) != 0) {
        broker_node_free(tokensNode);
        return 1;
    }

    tokenRootNode = broker_node_create("root", "node");
    if (!tokenRootNode) {
        return 1;
    }

    if (broker_node_add(tokensNode, tokenRootNode) != 0) {
        broker_node_free(tokenRootNode);
        return 1;
    }

    BrokerNode *addTokenAction = broker_node_create("add", "node");
    if (!addTokenAction) {
        return 1;
    }

    if (json_object_set_new_nocheck(addTokenAction->meta, "$invokable",
                            json_string_nocheck("config")) != 0) {
        broker_node_free(addTokenAction);
        return 1;
    }

    json_error_t err;
    json_t *paramList = json_loads("[{\"name\":\"TimeRange\",\"type\":\"string\",\"editor\":\"daterange\"},{\"name\":\"Count\",\"type\":\"number\",\"description\":\"how many times this token can be used\"},{\"name\":\"Managed\",\"type\":\"bool\",\"description\":\"when a managed token is deleted, server will delete all the dslinks associated with the token\"},{\"name\":\"Group\",\"type\":\"string\",\"description\":\"default permission group\"}]",
        0, &err);
    if (!paramList || json_object_set_new_nocheck(addTokenAction->meta, "$params", paramList) != 0) {
        return 1;
    }

    json_t *columnList = json_array();
    if (broker_invoke_create_param(columnList, "tokenName", "string") != 0
        || json_object_set_new_nocheck(addTokenAction->meta, "$columns", columnList) != 0) {
        return 1;
    }


    if (broker_node_add(tokenRootNode, addTokenAction) != 0) {
        broker_node_free(addTokenAction);
        return 1;
    }

    addTokenAction->on_invoke = add_token_invoke;

    return load_tokens();
}

