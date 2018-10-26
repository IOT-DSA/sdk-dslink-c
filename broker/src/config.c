#include <string.h>

#define LOG_TAG "config"
#include <dslink/log.h>
#include <dslink/mem/mem.h>

#include <uv.h>

#include <sys/param.h>
#include <dslink/utils.h>

#include "broker/config.h"
#define BROKER_CONF_LOC "broker.json"

static
json_t *broker_config = NULL;

static
json_t *broker_config_gen() {
    if (broker_config) {
        json_decref(broker_config);
    }
    broker_config = json_object();
    if (!broker_config) {
        goto exit;
    }

    json_t *http = json_object();
    {
        if (!http) {
            goto del_broker;
        }

        if (json_object_set_new_nocheck(broker_config, "http", http) != 0) {
            goto del_http;
        }

        {
            json_object_set_new_nocheck(http, "enabled", json_true());
            json_object_set_new_nocheck(http, "host", json_string_nocheck("0.0.0.0"));
            json_object_set_new_nocheck(http, "port", json_integer(8100));
        }
    }
    json_t *https = json_object();
    {
        if (!https) {
            goto del_broker;
        }

        if (json_object_set_new_nocheck(broker_config, "https", https) != 0) {
            goto del_https;
        }

        {
            json_object_set_new_nocheck(https, "enabled", json_true());
            json_object_set_new_nocheck(https, "host", json_string_nocheck("0.0.0.0"));
            json_object_set_new_nocheck(https, "port", json_integer(8463));
            json_object_set_new_nocheck(https, "certName", json_string_nocheck("server.pem"));
            json_object_set_new_nocheck(https, "certKeyName", json_string_nocheck("key.pem"));

        }
    }

    json_object_set_new_nocheck(broker_config, "log_level", json_string_nocheck("info"));
    json_object_set_new_nocheck(broker_config, "allowAllLinks", json_true());
    json_object_set_new_nocheck(broker_config, "maxQueue", json_integer(1024));
    json_object_set_new_nocheck(broker_config, "defaultPermission", json_null());

    json_t *storage = json_object();

    {
        char cwd[MAXPATHLEN] = ".";

        size_t *size = dslink_malloc(sizeof(size_t));
        if (uv_cwd(cwd, size) != 0) {
            cwd[0] = '.';
        }
        dslink_free(size);

        json_object_set_new_nocheck(storage, "path", json_string_nocheck(cwd));
    }

    json_object_set_new_nocheck(broker_config, "storage", storage);

    if (json_dump_file(broker_config, BROKER_CONF_LOC,
                       JSON_PRESERVE_ORDER | JSON_INDENT(2)) != 0) {
        log_fatal("Failed to save broker configuration\n");
        goto del_broker;
    } else {
        log_info("Created broker and saved the default broker configuration\n");
    }

    goto exit;

del_https:
    json_decref(https);
del_http:
    json_decref(http);
del_broker:
    json_decref(broker_config);
    broker_config = NULL;
exit:
    return broker_config;
}


json_t *broker_config_get() {
    if (broker_config) {
        json_decref(broker_config);
    }

    json_error_t err;
    broker_config = json_load_file(BROKER_CONF_LOC, 0, &err);
    if (!broker_config) {
        if (strcmp(BROKER_CONF_LOC, err.source) != 0) {
            log_err("Failed to load broker configuration: %s\n", err.text);
            return NULL;
        } else {
            return broker_config_gen();
        }
    }
    log_info("Broker configuration loaded\n");
    return broker_config;
}

uint8_t broker_enable_token = 1;
size_t broker_max_qos_queue_size = 1024;
char *broker_storage_path = ".";

int broker_change_default_permissions(json_t* json) {
    if (!broker_config) {
        return 1;
    }
    json_object_del(broker_config, "defaultPermission");
    json_object_set_nocheck(broker_config, "defaultPermission", json);

    if (json_dump_file(broker_config, BROKER_CONF_LOC,
                       JSON_PRESERVE_ORDER | JSON_INDENT(2)) != 0) {
        log_err("Failed to save broker configuration\n");
    }
    return 0;
}

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
        broker_enable_token = 1;
    } else {
        // true by default
        broker_enable_token = 0;
    }

    // load maxQueue
    json_t* maxQueue = json_object_get(json, "maxQueue");
    if (json_is_integer(maxQueue)) {
        broker_max_qos_queue_size = (size_t)json_integer_value(maxQueue);
        if (broker_max_qos_queue_size < 16) {
            broker_max_qos_queue_size = 16;
        } else if (broker_max_qos_queue_size > 0xFFFFF) {
            broker_max_qos_queue_size = 0xFFFFF;
        }
    }

    json_t *storage = json_object_get(json, "storage");

    if (json_is_object(storage)) {
        json_t *storagePath = json_object_get(storage, "path");

        if (json_is_string(storagePath)) {
            broker_storage_path = (char *) json_string_value(storagePath);
        }
    }

    return 0;
}

const char *broker_pathcat(const char *parent, const char *child) {
    if (*parent == '\0') {
        return dslink_strdup(child);
    }
    size_t size = strlen(parent) + strlen(child) + 2;
    char *path = dslink_malloc(size);
    snprintf(path, size, "%s/%s", parent, child);
    return path;
}

const char *broker_get_storage_path(char *child) {
    return broker_pathcat(broker_storage_path, child);
}
