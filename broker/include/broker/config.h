#ifndef BROKER_CONFIG_H
#define BROKER_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>

json_t *broker_config_get();

#ifdef __cplusplus
}
#endif

#endif // BROKER_CONFIG_H
