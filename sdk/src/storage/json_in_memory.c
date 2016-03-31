#include <dslink/storage/storage.h>
#include <dslink/storage/json_in_memory.h>
#include <string.h>

static
char *json_key_join(char *vals[]) {
    char *str = "";

    for (char **arg = vals; *arg; ++arg) {
        char *entry = *arg;
        size_t count = strlen(str) + strlen(entry) + 3;
        char *tmp = dslink_malloc(count);
        snprintf(tmp, count, "%s::%s", str, entry);
        str = tmp;
    }

    for (size_t i = 0; vals[i] != NULL; i++) {
        char *entry = vals[i];
        size_t count = strlen(str) + strlen(entry) + 3;
        char *tmp = dslink_malloc(count);
        snprintf(tmp, count, "%s::%s", str, entry);
        str = tmp;
    }
    return str;
}

static
void json_storage_init(StorageProvider *provider) {
    (void) provider;
}

static
void json_storage_push(StorageProvider *provider, char **rkey, json_t *value, storage_push_done_cb cb, void *data) {
    char *key = json_key_join(rkey);

    json_t *json = provider->data;
    json_t *array = json_object_get(json, key);
    if (!json_is_array(array)) {
        array = json_array();
        json_object_set_new(json, key, array);
    }

    json_incref(value);
    json_array_append_new(array, value);

    if (cb) {
        cb(data);
    }
}

static
void json_storage_pull(StorageProvider *provider, char **rkey, storage_pull_done_cb cb, void *data) {
    char *key = json_key_join(rkey);

    json_t *json = provider->data;
    json_t *array = json_object_get(json, key);
    if (!json_is_array(array)) {
        array = json_array();
        json_object_set_new(json, key, array);
    }

    if (json_array_size(array) <= 0) {
        if (cb) {
            cb(NULL, data);
        }
    } else {
        json_t *m = json_array_get(array, 0);
        json_array_remove(array, 0);

        if (cb) {
            cb(m, data);
        }
    }
}

static
json_t *json_storage_traverse(StorageProvider *provider) {
    return provider->data;
}

static
void json_storage_store(StorageProvider *provider, char **rkey, json_t *value, storage_store_done_cb cb, void *data) {
    char *key = json_key_join(rkey);

    json_t *json = provider->data;
    json_object_set_new(json, key, value);

    if (cb) {
        cb(data);
    }
}

static
void json_storage_recall(StorageProvider *provider, char **rkey, storage_recall_done_cb cb, void *data) {
    char *key = json_key_join(rkey);

    json_t *json = provider->data;
    json_t *val = json_object_get(json, key);

    if (cb) {
        cb(val, data);
    }
}

static
void json_storage_destroy(StorageProvider *provider) {
    json_t *json = provider->data;
    json_delete(json);
}

StorageProvider *dslink_storage_json_memory_create(char *path) {
    (void) path;
    StorageProvider *storage = dslink_malloc(sizeof(StorageProvider));
    storage->data = json_object();

    storage->init_cb = json_storage_init;
    storage->destroy_cb = json_storage_destroy;

    storage->push_cb = json_storage_push;
    storage->pull_cb = json_storage_pull;

    storage->traverse_cb = json_storage_traverse;

    storage->store_cb = json_storage_store;
    storage->recall_cb = json_storage_recall;
    return storage;
}
