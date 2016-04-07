#ifndef SDK_DSLINK_C_STORAGE_STORAGE_H
#define SDK_DSLINK_C_STORAGE_STORAGE_H

#include <jansson.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

struct StorageProvider;

typedef void (*storage_gen_done_cb)(void *data);
typedef void (*storage_recall_done_cb)(json_t *value, void *data);

typedef void (*storage_push_done_cb)(void *data);
typedef void (*storage_pull_done_cb)(json_t *value, void *data);

typedef void (*storage_store_cb)(
    struct StorageProvider *provider,
    const char **key,
    json_t *value,
    storage_gen_done_cb cb,
    void *data
);

typedef void (*storage_recall_cb)(
    struct StorageProvider *provider,
    const char **key,
    storage_recall_done_cb cb,
    void *data
);

typedef void (*storage_push_cb)(
    struct StorageProvider *provider,
    const char **key,
    json_t *value,
    storage_push_done_cb cb,
    void *data
);

typedef void (*storage_pull_cb)(
    struct StorageProvider *provider,
    const char **key,
    storage_pull_done_cb cb,
    void *data
);

typedef void (*storage_init_cb)(struct StorageProvider *provider);
typedef void (*storage_destroy_cb)(struct StorageProvider *provider);
typedef void (*storage_destroy_group_cb)(struct StorageProvider *provider, char *group);

typedef json_t* (*storage_traverse_cb)(struct StorageProvider *provider);

typedef struct StorageProvider {
    storage_init_cb init_cb;
    storage_destroy_cb destroy_cb;

    storage_store_cb store_cb;
    storage_recall_cb recall_cb;

    storage_pull_cb pull_cb;
    storage_push_cb push_cb;
    storage_destroy_group_cb destroy_group_cb;

    storage_traverse_cb traverse_cb;

    void *data;
    uv_loop_t *loop;
} StorageProvider;

StorageProvider *dslink_storage_init(json_t *config);
void dslink_storage_destroy(StorageProvider *provider);

json_t *dslink_storage_traverse(StorageProvider *provider);

void dslink_storage_push(StorageProvider *provider, const char *group, const char *key, json_t *value, storage_push_done_cb cb, void *data);
void dslink_storage_pull(StorageProvider *provider, const char *group, const char *key, storage_pull_done_cb cb, void *data);

void dslink_storage_store(StorageProvider *provider, const char *group, const char *key, json_t *value, storage_gen_done_cb cb, void *data);
void dslink_storage_recall(StorageProvider *provider, const char *group, const char *key, storage_recall_done_cb cb, void *data);
void dslink_storage_destroy_group(StorageProvider *provider, char *group);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_STORAGE_STORAGE_H
