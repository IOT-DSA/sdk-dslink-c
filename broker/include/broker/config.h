#ifndef BROKER_CONFIG_H
#define BROKER_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>

json_t *broker_config_get();

extern uint8_t broker_enable_token;
extern size_t broker_max_qos_queue_size;

int broker_config_load(json_t *json);
const char *broker_pathcat(const char *parent, const char *child);
const char *broker_get_storage_path(char *path);

#ifdef __cplusplus
}
#endif

#endif // BROKER_CONFIG_H
