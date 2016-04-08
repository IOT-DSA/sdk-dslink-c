#include <dslink/storage/storage.h>
#include <dslink/storage/json_file.h>
#include <uv.h>
#include <string.h>
#include <dslink/utils.h>

typedef struct JsonStore {
    char *path;
    json_t *root;
    uv_timer_t *save_timer;
    json_t *save_queue;
    uint loaded;
    uint timer_setup;
    uint waiting;
} JsonStore;

static
void json_storage_init(StorageProvider *provider) {
    (void) provider;
}

static
void fs_close_cb(uv_fs_t *req) {
    void **data = req->data;
    JsonStore *store = data[2];

    if (store->waiting > 0) {
        store->waiting--;
    }

    uv_fs_req_cleanup(req);
    dslink_free(req);
    dslink_free(data);
}

static
void json_file_ignore_write(uv_fs_t *req) {
    void **data = req->data;
    char *str = data[1];

    uv_fs_t *close_req = dslink_malloc(sizeof(uv_fs_t));
    close_req->data = req->data;
    uv_fs_close(req->loop, close_req, req->file, fs_close_cb);

    uv_fs_req_cleanup(req);
    dslink_free(req);
    dslink_free(str);
}

static
void json_file_open_write(uv_fs_t *req) {
    void **data = req->data;

    char *str = data[1];

    uv_buf_t *buf = dslink_malloc(sizeof(uv_buf_t));
    buf->base = str;
    buf->len = strlen(str);

    uv_loop_t *loop = req->loop;

    uv_fs_t *write_req = dslink_malloc(sizeof(uv_fs_t));
    write_req->data = req->data;
    uv_fs_write(loop, write_req, (uv_file) req->result, buf, 1, 0, json_file_ignore_write);
    uv_fs_req_cleanup(req);
    dslink_free(req);
}

static
void json_storage_init_open_write(uv_fs_t *req) {
    void **data = req->data;

    char *path = data[0];

    uv_fs_t *open_req = dslink_malloc(sizeof(uv_fs_t));
    open_req->data = data;
    uv_fs_open(req->loop, open_req, path, O_WRONLY | O_CREAT | O_TRUNC, 0770, json_file_open_write);
    uv_fs_req_cleanup(req);
    dslink_free(req);
    dslink_free(path);
}

static
void nop_close_uv(uv_handle_t *handle) {
    dslink_free(handle);
}

static
void json_storage_handle_save_tick(uv_timer_t *timer);

static
void json_storage_init_save_timer(StorageProvider *provider) {
    JsonStore *store = provider->data;
    if (store->timer_setup != 0) {
        uv_timer_stop(store->save_timer);
        uv_close((uv_handle_t *) store->save_timer, nop_close_uv);
    }

    uv_timer_init(provider->loop, store->save_timer);
    store->save_timer->data = provider;
    uv_timer_start(store->save_timer, json_storage_handle_save_tick, 5, 1000);
    store->timer_setup = 1;
}

static
void json_storage_trigger_save(StorageProvider *provider, const char **rkey) {
    JsonStore *store = provider->data;

    if (store->timer_setup == 0) {
        json_storage_init_save_timer(provider);
    }

    const char *keyA = rkey[0];
    const char *keyB = rkey[1];

    json_t *levelA = json_object_get(store->root, keyA);

    if (!levelA) {
        levelA = json_object();
        json_object_set_new(store->root, keyA, levelA);
    }

    json_t *levelB = json_object_get(levelA, keyB);

    char *tm = dslink_malloc(256);
    memset(tm, 0, 256);

    sprintf(tm, "%s/%s/%s", store->path, keyA, keyB);

    if (!levelB) {
        store->waiting--;
        uv_fs_t req;
        uv_fs_unlink(provider->loop, &req, tm, NULL);
        uv_fs_req_cleanup(&req);
        dslink_free(tm);
        return;
    }

    char *encoded = json_dumps(levelB, JSON_ENCODE_ANY);
    void **pass = dslink_malloc(sizeof(tm) + sizeof(encoded) + sizeof(JsonStore*));
    pass[0] = tm;
    pass[1] = encoded;
    pass[2] = store;

    {
        uv_fs_t *mkreq = dslink_malloc(sizeof(uv_fs_t));

        mkreq->data = pass;

        size_t width =  strrchr(tm, '/') - tm;
        char *dirpath = dslink_malloc(width + 1);
        memcpy(dirpath, tm, width);
        dirpath[width] = '\0';
        uv_fs_mkdir(provider->loop, mkreq, dirpath, 0770, json_storage_init_open_write);
    }
}

static
void json_storage_handle_save_tick(uv_timer_t *timer) {
    StorageProvider *provider = timer->data;
    JsonStore *store = provider->data;

    if (store->waiting > 0) {
        return;
    }

    const char *key;
    json_t *entry;
    json_object_foreach(store->save_queue, key, entry) {
        const char *keyA = json_string_value(json_array_get(entry, 0));
        const char *keyB = json_string_value(json_array_get(entry, 1));

        const char *rkey[] = {
            dslink_strdup(keyA),
            dslink_strdup(keyB)
        };

        json_storage_trigger_save(provider, (const char **) rkey);
        store->waiting++;
    }

    json_object_clear(store->save_queue);
}

static
void json_storage_push(StorageProvider *provider, const char **rkey, json_t *value, storage_push_done_cb cb, void *data) {
    const char *keyA = rkey[0];
    const char *keyB = rkey[1];

    JsonStore *store = provider->data;
    json_t *levelA = json_object_get(store->root, keyA);

    if (!levelA) {
        levelA = json_object();
        json_object_set_new(store->root, keyA, levelA);
    }

    json_t *levelB = json_object_get(levelA, keyB);

    if (!levelB) {
        levelB = json_array();
        json_object_set_new(levelA, keyB, levelB);
    }

    json_array_insert_new(levelB, 0, value);

    json_t *sub = json_array();
    json_array_append_new(sub, json_string_nocheck(keyA));
    json_array_append_new(sub, json_string_nocheck(keyB));
    size_t z =  strlen(keyA) + strlen(keyB) + 1;
    char *keyFull = dslink_malloc(z);
    sprintf(keyFull, "%s%s", keyA, keyB);
    json_object_set_nocheck(store->save_queue, keyFull, sub);
    dslink_free(keyFull);

    json_storage_trigger_save(provider, rkey);

    if (cb) {
        cb(data);
    }
}

static
void json_storage_pull(StorageProvider *provider, const char **rkey, storage_pull_done_cb cb, void *data) {
    const char *keyA = rkey[0];
    const char *keyB = rkey[1];

    JsonStore *store = provider->data;
    json_t *levelA = json_object_get(store->root, keyA);

    if (!levelA) {
        levelA = json_object();
        json_object_set_new(store->root, keyA, levelA);
    }

    json_t *levelB = json_object_get(levelA, keyB);

    if (!levelB) {
        levelB = json_array();
        json_object_set_new(levelA, keyB, levelB);
    }

    if (json_array_size(levelB) <= 0) {
        if (cb) {
            cb(NULL, data);
        }
    } else {
        json_t *pulled = json_array_get(levelB, 0);
        json_array_remove(levelB, 0);

        json_t *sub = json_array();
        json_array_append_new(sub, json_string_nocheck(keyA));
        json_array_append_new(sub, json_string_nocheck(keyB));
        size_t z =  strlen(keyA) + strlen(keyB) + 1;
        char *keyFull = dslink_malloc(z);
        sprintf(keyFull, "%s%s", keyA, keyB);
        json_object_set_nocheck(store->save_queue, keyFull, sub);
        dslink_free(keyFull);

        json_storage_trigger_save(provider, rkey);

        if (cb) {
            cb(pulled, data);
        }
    }
}

static
json_t *json_storage_load(StorageProvider *provider) {
    JsonStore *store = provider->data;

    if (store->loaded == 1) {
        return store->root;
    }

    uv_fs_t dir;

    json_t *root = json_object();
    json_t *names = json_array();

    uv_fs_mkdir(NULL, &dir, store->path, 0770, NULL);

    if (uv_fs_scandir(NULL, &dir, store->path, 0, NULL) < 0) {
        goto exit;
    }

    uv_dirent_t d;

    while (uv_fs_scandir_next(&dir, &d) != UV_EOF) {
        if (d.type != UV_DIRENT_DIR) {
            continue;
        }

        json_array_append_new(names, json_string_nocheck(d.name));
        json_object_set_new(root, d.name, json_object());
    }

    size_t index;
    json_t *name;

    json_array_foreach(names, index, name) {
        const char *n = json_string_value(name);

        char tm[256];

        {
            int len = snprintf(tm, sizeof(tm) - 1, "%s/%s", store->path, n);
            tm[len] = '\0';
        }

        json_t *mine = json_object_get(root, n);

        uv_fs_t dirf;
        if (uv_fs_scandir(NULL, &dirf, tm, 0, NULL) > 0) {
            while (uv_fs_scandir_next(&dirf, &d) != UV_EOF) {
                if (d.type != UV_DIRENT_FILE) {
                    continue;
                }

                char tmp[256];
                int len = snprintf(tmp, sizeof(tmp) - 1, "%s/%s/%s", store->path, n, d.name);
                tmp[len] = '\0';

                json_error_t err;
                json_t *val = json_load_file(tmp, JSON_DECODE_ANY, &err);

                if (val) {
                    json_object_set_new(mine, d.name, val);
                }
            }
        }
    }

    exit:
    json_decref(names);
    store->loaded = 1;
    store->root = root;
    return root;
}

static
void json_storage_store(StorageProvider *provider, const char **rkey, json_t *value, storage_gen_done_cb cb, void *data) {
    const char *keyA = rkey[0];
    const char *keyB = rkey[1];

    JsonStore *store = provider->data;
    json_t *levelA = json_object_get(store->root, keyA);

    if (!levelA) {
        levelA = json_object();
        json_object_set_new(store->root, keyA, levelA);
    }

    if (!value) {
        json_object_del(levelA, keyB);
    } else {
        json_object_set_nocheck(levelA, keyB, value);
    }

    json_t *sub = json_array();
    json_array_append_new(sub, json_string_nocheck(keyA));
    json_array_append_new(sub, json_string_nocheck(keyB));
    size_t z =  strlen(keyA) + strlen(keyB) + 1;
    char *keyFull = dslink_malloc(z);
    sprintf(keyFull, "%s%s", keyA, keyB);
    json_object_set_nocheck(store->save_queue, keyFull, sub);
    dslink_free(keyFull);

    json_storage_trigger_save(provider, rkey);

    if (cb) {
        cb(data);
    }
}

static
void json_storage_recall(StorageProvider *provider, const char **rkey, storage_recall_done_cb cb, void *data) {
    const char *keyA = rkey[0];
    const char *keyB = rkey[1];

    JsonStore *store = provider->data;

    json_t *levelA = json_object_get(store->root, keyA);

    if (!levelA) {
        levelA = json_object();
        json_object_set_new(store->root, keyA, levelA);
    }

    json_t *levelB = json_object_get(levelA, keyB);

    if (cb) {
        cb(levelB, data);
    }
}

static
void json_storage_destroy(StorageProvider *provider) {
    JsonStore *store = provider->data;

    if (store->timer_setup != 0) {
        dslink_free(store->save_timer);
        uv_timer_stop(store->save_timer);
        uv_close((uv_handle_t *) store->save_timer, nop_close_uv);
        store->timer_setup = 0;
    }

    json_delete(store->root);
    json_delete(store->save_queue);
    dslink_free(store->path);
    dslink_free(store);
}

static
void json_storage_destroy_group(StorageProvider *provider, char *group) {
    JsonStore *store = provider->data;

    char tm[256];

    {
        int len = snprintf(tm, sizeof(tm) - 1, "%s/%s", store->path, group);
        tm[len] = '\0';
    }

    uv_fs_t dirf;
    uv_dirent_t d;
    if (uv_fs_scandir(NULL, &dirf, tm, 0, NULL) > 0) {
        while (uv_fs_scandir_next(&dirf, &d) != UV_EOF) {
            if (d.type != UV_DIRENT_FILE) {
                continue;
            }

            char tmp[256];
            int len = snprintf(tmp, sizeof(tmp) - 1, "%s/%s/%s", store->path, group, d.name);
            tmp[len] = '\0';

            uv_fs_t req;
            uv_fs_unlink(provider->loop, &req, tmp, NULL);
            uv_fs_req_cleanup(&req);
        }
    }

    uv_fs_t req;
    uv_fs_rmdir(provider->loop, &req, tm, NULL);
    uv_fs_req_cleanup(&req);
}

StorageProvider *dslink_storage_json_file_create(char *path) {
    StorageProvider *storage = dslink_malloc(sizeof(StorageProvider));
    JsonStore *store = storage->data = dslink_malloc(sizeof(JsonStore));
    storage->loop = uv_default_loop();
    store->root = json_object();
    store->path = path;
    store->save_queue = json_object();
    store->save_timer = dslink_malloc(sizeof(uv_timer_t));
    store->loaded = 0;
    store->timer_setup = 0;
    store->waiting = 0;

    storage->init_cb = json_storage_init;
    storage->destroy_cb = json_storage_destroy;

    storage->push_cb = json_storage_push;
    storage->pull_cb = json_storage_pull;

    storage->traverse_cb = json_storage_load;

    storage->store_cb = json_storage_store;
    storage->recall_cb = json_storage_recall;
    storage->destroy_group_cb = json_storage_destroy_group;
    return storage;
}
