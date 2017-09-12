#define LOG_TAG "dslink"
#include "dslink/log.h"

#include <argtable3.h>
#include <string.h>
#include <wslay/wslay.h>
#include <jansson.h>

#include "dslink/handshake.h"
#include "dslink/utils.h"
#include "dslink/ws.h"

#define SECONDS_TO_MILLIS(count) count * 1000

#define DSLINK_RESPONDER_MAP_INIT(var, type) \
    responder->var = dslink_calloc(1, sizeof(Map)); \
    if (!responder->var) { \
        goto cleanup; \
    } \
    if (dslink_map_init(responder->var, \
            dslink_map_##type##_cmp, \
            dslink_map_##type##_key_len_cal, \
            dslink_map_hash_key) != 0) { \
        dslink_free(responder->var); \
        responder->var = NULL; \
        goto cleanup; \
    }

#define DSLINK_REQUESTER_MAP_INIT(var, type) \
    requester->var = dslink_calloc(1, sizeof(Map)); \
    if (!requester->var) { \
        goto cleanup; \
    } \
    if (dslink_map_init(requester->var, \
            dslink_map_##type##_cmp, \
            dslink_map_##type##_key_len_cal, \
            dslink_map_hash_key) != 0) { \
        dslink_free(requester->var); \
        requester->var = NULL; \
        goto cleanup; \
    }

static inline
void dslink_print_help() {
    printf("See --help for usage\n");
}

static
int dslink_parse_opts(int argc,
                      char **argv,
                      DSLinkConfig *config) {
    int ret = 0;

    json_t *json = NULL;

    struct arg_lit *help;
    struct arg_str *broker, *token, *log, *name;
    struct arg_end *end;

    void *argTable[] = {
        help = arg_lit0("h", "help", "Displays this help menu"),
        broker = arg_str0("b", "broker", "url", "Sets the broker URL to connect to"),
        token = arg_str0("t", "token", NULL, "Sets the token"),
        log = arg_str0("l", "log", "log type", "Sets the logging level"),
        name = arg_str0("n", "name", NULL, "Sets the dslink name"),
        end = arg_end(6)
    };

    if (arg_nullcheck(argTable) != 0) {
        return DSLINK_ALLOC_ERR;
    }

    int errs = arg_parse(argc, argv, argTable);

    if (help->count > 0) {
        printf("Usage: <opts>\n");
        arg_print_glossary(stdout, argTable, " %-25s %s\n");
        ret = 1;
        goto exit;
    }

    if (errs > 0) {
        dslink_print_help();
        arg_print_errors(stdout, end, ":");
        ret = 1;
        goto exit;
    }

    const char *brokerUrl;
    json = dslink_read_dslink_json();

    if (broker->count > 0) {
        brokerUrl = broker->sval[0];
    } else {
        json_t *str = dslink_json_raw_get_config(json, "broker");
        if (json_is_string(str)) {
            brokerUrl = json_string_value(str);
        } else {
            brokerUrl = "http://127.0.0.1:8080/conn";
        }
    }
    config->broker_url = dslink_url_parse(brokerUrl);

    if (token->count > 0) {
        config->token = token->sval[0];
    } else if (json) {
        json_t *str = dslink_json_raw_get_config(json, "token");
        if (str) {
            config->token = json_string_value(str);
        }
    }

    if (name->count > 0) {
        config->name = name->sval[0];
    } else if (json) {
        json_t *str = dslink_json_raw_get_config(json, "name");
        if (str) {
            config->name = json_string_value(str);
        }
    }

    if (!config->broker_url) {
        log_fatal("Failed to parse broker url\n");
        ret = 1;
        goto exit;
    }

    if (log->count > 0) {
        const char *lvl = log->sval[0];
        if (dslink_log_set_lvl(lvl) != 0) {
            printf("Invalid log level: %s\n", lvl);
            dslink_print_help();
            ret = 1;
            goto exit;
        }
    } else {
        json_t *lvl = dslink_json_raw_get_config(json, "log");
        if (json_is_string(lvl)) {
            if (dslink_log_set_lvl(json_string_value(lvl)) != 0) {
                printf("Invalid log level: %s\n", json_string_value(lvl));
                dslink_print_help();
                ret = 1;
                goto exit;
            }
        }
    }

exit:
    arg_freetable(argTable, sizeof(argTable) / sizeof(argTable[0]));
    if (json) {
        json_decref(json);
    }
    return ret;
}

static
int dslink_init_responder(Responder *responder) {
    responder->super_root = dslink_node_create(NULL, "/", "node");
    if (!responder->super_root) {
        goto cleanup;
    }

    DSLINK_RESPONDER_MAP_INIT(open_streams, uint32)
    DSLINK_RESPONDER_MAP_INIT(list_subs, str)
    DSLINK_RESPONDER_MAP_INIT(value_path_subs, str)
    DSLINK_RESPONDER_MAP_INIT(value_sid_subs, uint32)
    return 0;
cleanup:
    if (responder->open_streams) {
        dslink_map_free(responder->open_streams);
    }
    if (responder->list_subs) {
        dslink_map_free(responder->list_subs);
    }
    if (responder->value_path_subs) {
        dslink_map_free(responder->value_path_subs);
    }
    if (responder->value_sid_subs) {
        dslink_map_free(responder->value_sid_subs);
    }
    if (responder->super_root) {
        dslink_node_tree_free(NULL, responder->super_root);
    }
    return DSLINK_ALLOC_ERR;
}

static
int dslink_init_requester(Requester *requester) {
    DSLINK_REQUESTER_MAP_INIT(open_streams, uint32)
    DSLINK_REQUESTER_MAP_INIT(list_subs, str)
    DSLINK_REQUESTER_MAP_INIT(request_handlers, uint32)
    DSLINK_REQUESTER_MAP_INIT(value_handlers, uint32)

    requester->rid = dslink_malloc(sizeof(uint32_t));
    *requester->rid = 0;
    requester->sid = dslink_malloc(sizeof(uint32_t));
    *requester->sid = 0;

    return 0;
    cleanup:
    if (requester->open_streams) {
        dslink_map_free(requester->open_streams);
    }

    if (requester->list_subs) {
        dslink_map_free(requester->list_subs);
    }

    if (requester->value_handlers) {
        dslink_map_free(requester->value_handlers);
    }

    if (requester->rid) {
        dslink_free(requester->rid);
    }

    if (requester->sid) {
        dslink_free(requester->sid);
    }

    return DSLINK_ALLOC_ERR;
}

static
int handle_config(DSLinkConfig *config, const char *name, int argc, char **argv) {
    memset(config, 0, sizeof(DSLinkConfig));
    config->name = name;

    int ret = 0;
    if ((ret = dslink_parse_opts(argc, argv, config)) != 0) {
        if (ret == DSLINK_ALLOC_ERR) {
            log_fatal("Failed to allocate memory during argument parsing\n");
        }
        return ret;
    }

    return ret;
}

int dslink_handle_key(DSLink *link) {
    int ret;
    if ((ret = dslink_handshake_key_pair_fs(&link->key, ".key")) != 0) {
        if (ret == DSLINK_CRYPT_KEY_DECODE_ERR) {
            log_fatal("Failed to decode existing key\n");
        } else if (ret == DSLINK_OPEN_FILE_ERR) {
            log_fatal("Failed to write generated key to disk\n");
        } else if (ret == DSLINK_CRYPT_KEY_PAIR_GEN_ERR) {
            log_fatal("Failed to generate key\n");
        } else {
            log_fatal("Unknown error occurred during key handling: %d\n", ret);
        }
    }
    return ret;
}

void dslink_close(DSLink *link) {
    link->closing = 1;
    wslay_event_queue_close(link->_ws, WSLAY_CODE_NORMAL_CLOSURE, NULL, 0);
    uv_stop(&link->loop);
}

static
void dslink_link_clear(DSLink *link) {
    if (link->_ws) {
        wslay_event_context_free(link->_ws);
    }

    if (link->msg) {
        dslink_free(link->msg);
    }

    if (link->link_data) {
        json_decref(link->link_data);
    }

    if (link->dslink_json) {
        json_decref(link->dslink_json);
    }
}

void dslink_link_free(DSLink *link) {
    dslink_link_clear(link);
    dslink_free(link);
}

json_t *dslink_read_dslink_json() {
    json_error_t err;
    json_t *json = json_load_file("dslink.json", JSON_DECODE_ANY, &err);

    if (!json) {
        log_warn("Failed to load dslink.json: %s\n", err.text);
        return NULL;
    }

    if (!json_is_object(json)) {
        log_warn("Failed to load dslink.json: Root is not a JSON object.\n");
        return NULL;
    }

    return json;
}

json_t *dslink_json_raw_get_config(json_t *json, const char *key) {
    if (!json_is_object(json)) {
        return NULL;
    }

    json_t *configs = json_object_get(json, "configs");

    if (!json_is_object(configs)) {
        return NULL;
    }

    json_t *section = json_object_get(configs, key);

    if (!json_is_object(section)) {
        return NULL;
    }

    json_t *value = json_object_get(section, "value");

    if (value) {
        return value;
    }

    json_t *defaultValue = json_object_get(section, "default");

    if (defaultValue) {
        return defaultValue;
    }

    return NULL;
}

json_t *dslink_json_get_config(DSLink *link, const char *key) {
    if (!link) {
        return NULL;
    }

    return dslink_json_raw_get_config(link->dslink_json, key);
}

static
int dslink_init_do(DSLink *link, DSLinkCallbacks *cbs) {
    link->closing = 0;

    link->msg = dslink_malloc(sizeof(uint32_t));
    *link->msg = 0;

    json_t *handshake = NULL;
    char *dsId = NULL;
    Socket *sock = NULL;

    int ret = 0;
    if (dslink_handle_key(link) != 0) {
        ret = 1;
        goto exit;
    }

    if (link->is_responder) {
        link->responder = dslink_calloc(1, sizeof(Responder));

        if (!link->responder) {
            log_fatal("Failed to create responder\n");
            goto exit;
        }

        if (dslink_init_responder(link->responder) != 0) {
            log_fatal("Failed to initialize responder\n");
            goto exit;
        }
    }

    if (link->is_requester) {
        link->requester = dslink_calloc(1, sizeof(Requester));
        if (!link->requester) {
            log_fatal("Failed to create requester\n");
            goto exit;
        }

        if (dslink_init_requester(link->requester) != 0) {
            log_fatal("Failed to initialize requester\n");
            goto exit;
        }
    }

    link->dslink_json = dslink_read_dslink_json();

    if (cbs->init_cb) {
        cbs->init_cb(link);
    }


    if ((ret = dslink_handshake_generate(link, &handshake, &dsId)) != 0) {
        log_fatal("Handshake failed: %d\n", ret);
        ret = 2;
        goto exit;
    }

    const char *uri = json_string_value(json_object_get(handshake, "wsUri"));
    const char *tKey = json_string_value(json_object_get(handshake, "tempKey"));
    const char *salt = json_string_value(json_object_get(handshake, "salt"));

    if (!(uri && ((tKey && salt) || link->config.token))) {
        log_fatal("Handshake didn't return the "
                      "necessary parameters to complete\n");
        ret = 2;
        goto exit;
    }

    if ((ret = dslink_handshake_connect_ws(link->config.broker_url, &link->key, uri,
                                           tKey, salt, dsId, link->config.token, &sock)) != 0) {
        log_fatal("Failed to connect to the broker: %d\n", ret);
        ret = 2;
        goto exit;
    } else {
        log_info("Successfully connected to the broker\n");
    }

    link->_socket = sock;

    if (cbs->on_connected_cb) {
        cbs->on_connected_cb(link);
    }

    dslink_handshake_handle_ws(link, cbs->on_requester_ready_cb);

    log_warn("Disconnected from the broker\n")
    if (cbs->on_disconnected_cb) {
        cbs->on_disconnected_cb(link);
    }

    if (link->closing != 1) {
        ret = 2;
    }

    exit:
    if (link->is_responder) {
        if (link->responder->super_root) {
            dslink_node_tree_free(link, link->responder->super_root);
        }

        if (link->responder->open_streams) {
            dslink_map_free(link->responder->open_streams);
            dslink_free(link->responder->open_streams);
        }

        if (link->responder->list_subs) {
            dslink_map_free(link->responder->list_subs);
            dslink_free(link->responder->list_subs);
        }

        if (link->responder->value_path_subs) {
            dslink_map_free(link->responder->value_path_subs);
            dslink_free(link->responder->value_path_subs);
        }

        if (link->responder->value_sid_subs) {
            dslink_map_free(link->responder->value_sid_subs);
            dslink_free(link->responder->value_sid_subs);
        }

        dslink_free(link->responder);
    }

    if (link->is_requester) {
        if (link->requester->list_subs) {
            dslink_map_free(link->requester->list_subs);
            dslink_free(link->requester->list_subs);
        }

        if (link->requester->request_handlers) {
            dslink_map_free(link->requester->request_handlers);
            dslink_free(link->requester->request_handlers);
        }

        if (link->requester->open_streams) {
            dslink_map_free(link->requester->open_streams);
            dslink_free(link->requester->open_streams);
        }

        if (link->requester->value_handlers) {
            dslink_map_free(link->requester->value_handlers);
            dslink_free(link->requester->value_handlers);
        }

        if (link->requester->rid) {
            dslink_free(link->requester->rid);
        }

        if (link->requester->sid) {
            dslink_free(link->requester->sid);
        }

        dslink_free(link->requester);
    }

    mbedtls_ecdh_free(&link->key);
    DSLINK_CHECKED_EXEC(dslink_socket_close, sock);
    DSLINK_CHECKED_EXEC(dslink_free, dsId);
    DSLINK_CHECKED_EXEC(json_delete, handshake);

    return ret;
}

//thread-safe API async handle callbacks
void dslink_async_get_node_value(uv_async_t *async_handle) {

    DSLinkAsyncGetData *async_data = (DSLinkAsyncGetData*)async_handle->data;

    DSLink *link = (DSLink*)(async_handle->loop->data);
    if(!link) {
        log_info("DSLink not found!\n");
    } else {
        DSNode *node = dslink_node_get_path(link->responder->super_root,async_data->node_path);
        if(node) {
            if(async_data->callback) {
                async_data->callback(json_copy(node->value),async_data->callback_data);
            }

        } else {
            log_info("Node not found in the path\n");
        }
    }

    //free async_data which is allocated in API func
    dslink_free(async_data->node_path);
    dslink_free(async_data);
}
void dslink_async_set_node_value(uv_async_t *async_handle) {

    DSLinkAsyncSetData *async_data = (DSLinkAsyncSetData*)async_handle->data;

    DSLink *link = (DSLink*)(async_handle->loop->data);
    if(!link) {
        log_warn("DSLink not found!\n");
    } else {
        DSNode *node = dslink_node_get_path(link->responder->super_root,async_data->node_path);
        int ret;
        if(node) {

            //json value's ref count must be 1 and should not be used in the other thread anymore
            if(dslink_node_update_value(link,node,async_data->set_value) == 0)
                ret = 0;
            else
                ret = -1;


        } else {
            log_info("Node not found in the path\n");
            ret = -1;
        }
        if(async_data->callback) {
            async_data->callback(ret,async_data->callback_data);
        }

    }

    //free async_data which is allocated in API func
    dslink_free(async_data->node_path);
    json_decref(async_data->set_value);
    dslink_free(async_data);

}
void dslink_async_run(uv_async_t *async_handle) {

    DSLinkAsyncRunData *async_data = (DSLinkAsyncRunData*)async_handle->data;

    DSLink *link = (DSLink*)(async_handle->loop->data);
    if(!link) {
        log_info("DSLink not found!\n");
    } else {
        if(async_data->callback) {
            async_data->callback(link,async_data->callback_data);
        }
    }

    //free async_data which is allocated in API func
    dslink_free(async_data);
}

int dslink_init(int argc, char **argv,
                const char *name, uint8_t isRequester,
                uint8_t isResponder, DSLinkCallbacks *cbs) {
    DSLink *link = dslink_malloc(sizeof(DSLink));
    bzero(link, sizeof(DSLink));
    uv_loop_init(&link->loop);
    link->loop.data = link;

    //thread-safe API async handle set
    if(uv_async_init(&link->loop, &link->async_get, dslink_async_get_node_value)) {
        log_warn("Async handle init error\n");
    }
    if(uv_async_init(&link->loop, &link->async_set, dslink_async_set_node_value)) {
        log_warn("Async handle init error\n");
    }
    if(uv_async_init(&link->loop, &link->async_run, dslink_async_run)) {
        log_warn("Async handle init error\n");
    }

    link->is_responder = isResponder;
    link->is_requester = isRequester;

    if (handle_config(&link->config, name, argc, argv) != 0) {
        return 1;
    }

    int ret = 0;
    while (1) {
        ret = dslink_init_do(link, cbs);
        if (ret != 2) {
            log_info("%i\n", ret);
            break;
        }
        
        dslink_link_clear(link);
        dslink_sleep(SECONDS_TO_MILLIS(5));
        log_info("Attempting to reconnect...\n");
    }

    uv_close((uv_handle_t*)&link->async_set,NULL);
    uv_close((uv_handle_t*)&link->async_get,NULL);
    uv_close((uv_handle_t*)&link->async_run,NULL);

    uv_loop_close(&link->loop);
    dslink_link_free(link);

    return ret;
}
