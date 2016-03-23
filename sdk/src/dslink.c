#define LOG_TAG "dslink"
#include "dslink/log.h"

#include <argtable3.h>
#include <string.h>
#include "dslink/handshake.h"
#include "dslink/utils.h"
#include "dslink/ws.h"

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
    struct arg_lit *help;
    struct arg_str *broker, *log;
    struct arg_end *end;

    void *argTable[] = {
        help = arg_lit0("h", "help", "Displays this help menu"),
        broker = arg_str1("b", "broker", "url", "Sets the broker URL to connect to"),
        log = arg_str0("l", "log", "log type", "Sets the logging level"),
        end = arg_end(5)
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

    const char *brokerUrl = broker->sval[0];
    config->broker_url = dslink_url_parse(brokerUrl);
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
    }

exit:
    arg_freetable(argTable, sizeof(argTable) / sizeof(argTable[0]));
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

    requester->rid = dslink_malloc(sizeof(uint32_t));
    *requester->rid = 0;

    return 0;
    cleanup:
    if (requester->open_streams) {
        dslink_map_free(requester->open_streams);
    }

    if (requester->list_subs) {
        dslink_map_free(requester->list_subs);
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

static
int handle_key(DSLink *link) {
    int ret;
    if ((ret = dslink_handshake_key_pair_fs(&link->key, ".key")) != 0) {
        if (ret == DSLINK_CRYPT_KEY_DECODE_ERR) {
            log_fatal("Failed to decode existing key\n");
        } else if (ret == DSLINK_OPEN_FILE_ERR) {
            log_fatal("Failed to write generated key to disk\n");
        } else if (ret == DSLINK_CRYPT_KEY_PAIR_GEN_ERR) {
            log_fatal("Failed to generated key\n");
        } else {
            log_fatal("Unknown error occurred during key handling: %d\n", ret);
        }
    }
    return ret;
}

int dslink_init(int argc, char **argv,
                const char *name, uint8_t isRequester,
                uint8_t isResponder, DSLinkCallbacks *cbs) {
    DSLink link;
    memset(&link, 0, sizeof(DSLink));
    link.is_responder = isResponder;
    link.is_requester = isRequester;
    link.msg = dslink_malloc(sizeof(uint32_t));
    *link.msg = 0;
    if (handle_config(&link.config, name, argc, argv) != 0) {
        return 1;
    }

    json_t *handshake = NULL;
    char *dsId = NULL;
    Socket *sock = NULL;

    int ret = 0;
    if (handle_key(&link) != 0) {
        ret = 1;
        goto exit;
    }

    if (isResponder) {
        link.responder = dslink_calloc(1, sizeof(Responder));
        if (!link.responder) {
            log_fatal("Failed to create responder\n");
            goto exit;
        }

        if (dslink_init_responder(link.responder) != 0) {
            log_fatal("Failed to initialize responder\n");
            goto exit;
        }
    }

    if (isRequester) {
        link.requester = dslink_calloc(1, sizeof(Requester));
        if (!link.requester) {
            log_fatal("Failed to create requester\n");
            goto exit;
        }

        if (dslink_init_requester(link.requester) != 0) {
            log_fatal("Failed to initialize requester\n");
            goto exit;
        }
    }

    if (cbs->init_cb) {
        cbs->init_cb(&link);
    }

    if ((ret = dslink_handshake_generate(&link, &handshake, &dsId)) != 0) {
        log_fatal("Handshake failed: %d\n", ret);
        ret = 1;
        goto exit;
    }

    const char *uri = json_string_value(json_object_get(handshake, "wsUri"));
    const char *tKey = json_string_value(json_object_get(handshake, "tempKey"));
    const char *salt = json_string_value(json_object_get(handshake, "salt"));

    if (!(uri && tKey && salt)) {
        log_fatal("Handshake didn't return the "
                      "necessary parameters to complete\n");
        ret = 1;
        goto exit;
    }

    if ((ret = dslink_handshake_connect_ws(link.config.broker_url, &link.key, uri,
                                           tKey, salt, dsId, &sock)) != 0) {
        log_fatal("Failed to connect to the broker: %d\n", ret);
        ret = 1;
        goto exit;
    } else {
        log_info("Successfully connected to the broker\n");
    }

    link._socket = sock;

    dslink_handshake_handle_ws(&link, cbs);

    // TODO: automatic reconnecting
    log_warn("Disconnected from the broker\n")
    if (cbs->on_disconnected_cb) {
        cbs->on_disconnected_cb(&link);
    }

exit:
    if (link.responder) {
        if (link.responder->super_root) {
            dslink_node_tree_free(NULL, link.responder->super_root);
        }
        if (link.responder->open_streams) {
            dslink_map_free(link.responder->open_streams);
            dslink_free(link.responder->open_streams);
        }

        if (link.responder->list_subs) {
            dslink_map_free(link.responder->list_subs);
            dslink_free(link.responder->list_subs);
        }

        if (link.responder->value_path_subs) {
            dslink_map_free(link.responder->value_path_subs);
            dslink_free(link.responder->value_path_subs);
        }

        if (link.responder->value_sid_subs) {
            dslink_map_free(link.responder->value_sid_subs);
            dslink_free(link.responder->value_sid_subs);
        }

        dslink_free(link.responder);
    }

    if (link.requester) {
        if (link.requester->list_subs) {
            dslink_map_free(link.requester->list_subs);
            dslink_free(link.requester->list_subs);
        }

        if (link.requester->open_streams) {
            dslink_map_free(link.requester->open_streams);
            dslink_free(link.requester->open_streams);
        }

        dslink_free(link.requester);
    }

    mbedtls_ecdh_free(&link.key);
    dslink_url_free(link.config.broker_url);
    DSLINK_CHECKED_EXEC(dslink_socket_close, sock);
    DSLINK_CHECKED_EXEC(dslink_free, dsId);
    DSLINK_CHECKED_EXEC(json_delete, handshake);
    return ret;
}
