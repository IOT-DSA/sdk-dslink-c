#ifndef SDK_DSLINK_C_STORAGE_JSON_H
#define SDK_DSLINK_C_STORAGE_JSON_H

#include <dslink/storage/storage.h>
#include <dslink/mem/mem.h>

#ifdef __cplusplus
extern "C" {
#endif

StorageProvider *dslink_storage_json_memory_create(char *path);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_STORAGE_JSON_H
