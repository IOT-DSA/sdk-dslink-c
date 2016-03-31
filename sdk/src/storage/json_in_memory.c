#include <dslink/storage/storage.h>
#include <dslink/storage/json_in_memory.h>

static
void json_storage_init(StorageProvider *provider) {
    (void) provider;
}

static
void json_storage_push(StorageProvider *provider, char *key, json_t *value, storage_push_done_cb cb, void *data) {
    json_t *json = provider->data;
    json_t *array = json_object_get(json, key);
    if (!json_is_array(array)) {
        array = json_array();
        json_object_set_new(json, key, array);
    }

    json_incref(value);
    json_array_append_new(array, value);

    cb(data);
}

static
void json_storage_pull(StorageProvider *provider, char *key, storage_pull_done_cb cb, void *data) {
    json_t *json = provider->data;
    json_t *array = json_object_get(json, key);
    if (!json_is_array(array)) {
        array = json_array();
        json_object_set_new(json, key, array);
    }

    if (json_array_size(array) <= 0) {
        cb(NULL, data);
    } else {
        json_t *m = json_array_get(array, 0);
        json_array_remove(array, 0);
        cb(m, data);
    }
}

static
json_t *json_storage_traverse(StorageProvider *provider) {
    return provider->data;
}

static
void json_storage_store(StorageProvider *provider, char *key, json_t *value, storage_store_done_cb cb, void *data) {
    json_t *json = provider->data;
    json_object_set_new(json, key, value);
    cb(data);
}

static
void json_storage_recall(StorageProvider *provider, char *key, storage_recall_done_cb cb, void *data) {
    json_t *json = provider->data;
    json_t *val = json_object_get(json, key);
    cb(val, data);
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
