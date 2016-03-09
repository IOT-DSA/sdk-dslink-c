#include <string.h>

#define LOG_TAG "config"
#include <dslink/log.h>

#include "broker/config.h"
#define BROKER_CONF_LOC "broker.json"

static
json_t *broker_config_gen() {
    json_t *server = json_object();
    if (!server) {
        goto exit;
    }

    json_t *http = json_object();
    {
        if (!http) {
            goto del_server;
        }

        if (json_object_set_new_nocheck(server, "http", http) != 0) {
            goto del_http;
        }

        {
            json_object_set_new_nocheck(http, "enabled", json_true());
            json_object_set_new_nocheck(http, "host", json_string("0.0.0.0"));
            json_object_set_new_nocheck(http, "port", json_integer(8100));
        }
    }

    json_object_set_new_nocheck(server, "log_level", json_string("info"));
    json_object_set_new_nocheck(server, "allowAllLinks", json_true());

    if (json_dump_file(server, BROKER_CONF_LOC,
                       JSON_PRESERVE_ORDER | JSON_INDENT(2)) != 0) {
        log_fatal("Failed to save broker configuration\n");
        goto del_server;
    } else {
        log_info("Created and saved the default broker configuration\n");
    }

    goto exit;
del_http:
    json_delete(http);
del_server:
    json_delete(server);
    return NULL;
exit:
    return server;
}

json_t *broker_config_get() {
    json_error_t err;
    json_t *config = json_load_file(BROKER_CONF_LOC, 0, &err);
    if (!config) {
        if (strcmp(BROKER_CONF_LOC, err.source) != 0) {
            log_err("Failed to load broker configuration: %s\n", err.text);
            return NULL;
        } else {
            return broker_config_gen();
        }
    }
    log_info("Broker configuration loaded\n");
    return config;
}


uint8_t broker_enable_token = 1;

int broker_config_load(json_t* json) {
    // load log level
    json_t *jsonLog = json_object_get(json, "log_level");
    if (json_is_string(jsonLog)) {
        const char *str = json_string_value(jsonLog);
        if (dslink_log_set_lvl(str) != 0) {
            log_warn("Invalid log level in the broker configuration\n");
        }
    } else {
        log_warn("Missing `log_level` from the broker configuration\n");
    }

    // load allowAllLinks (use token or not)
    json_t* allowAllLinks = json_object_get(json, "allowAllLinks");
    if (json_is_false(allowAllLinks)) {
        broker_enable_token = 0;
    } else {
        // true by default
        broker_enable_token = 1;
    }

    return 0;
}
