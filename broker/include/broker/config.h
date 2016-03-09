#ifndef BROKER_CONFIG_H
#define BROKER_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>

json_t *broker_config_get();

extern uint8_t broker_enable_token;

int broker_config_load(json_t *json);

#ifdef __cplusplus
}
#endif

#endif // BROKER_CONFIG_H
