#include <dslink/storage/storage.h>
#include <dslink/storage/json_file.h>

StorageProvider *dslink_storage_init(json_t *config) {
    (void) config;

    json_t *jPath = json_object_get(config, "path");
    char *path;

    if (json_is_string(jPath)) {
        path = (char *) json_string_value(jPath);
    } else {
        path = "storage";
    }

    return dslink_storage_json_file_create(path);
}

void dslink_storage_destroy(StorageProvider *provider) {
    provider->destroy_cb(provider);
}

void dslink_storage_push(StorageProvider *provider, const char *group, const char *key, json_t *value, storage_push_done_cb cb, void *data) {
    const char *rkey[] = {
        group,
        key
    };

    provider->push_cb(provider, rkey, value, cb, data);
}

void dslink_storage_pull(StorageProvider *provider, const char *group, const char *key, storage_pull_done_cb cb, void *data) {
    const char *rkey[] = {
        group,
        key
    };

    provider->pull_cb(provider, rkey, cb, data);
}

void dslink_storage_store(StorageProvider *provider, const char *group, const char *key, json_t *value, storage_gen_done_cb cb, void *data) {
    const char *rkey[] = {
        group,
        key
    };

    provider->store_cb(provider, rkey, value, cb, data);
}

void dslink_storage_recall(StorageProvider *provider, const char *group, const char *key, storage_recall_done_cb cb, void *data) {
    const char *rkey[] = {
        group,
        key
    };
    provider->recall_cb(provider, rkey, cb, data);
}

void dslink_storage_destroy_group(StorageProvider *provider, char *group) {
    provider->destroy_group_cb(provider, group);
}

json_t *dslink_storage_traverse(StorageProvider *provider) {
    return provider->traverse_cb(provider);
}
