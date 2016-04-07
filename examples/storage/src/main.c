#include <dslink/storage/storage.h>
#include <uv.h>

StorageProvider *storage;

static
void print_json(json_t *json) {
    char *encoded = json_dumps(json, JSON_INDENT(2));
    printf("%s", encoded);
}

static
void on_val_save(void *data) {
    (void) data;
    json_t *json = dslink_storage_traverse(storage);
    print_json(json);
    printf("\n");
}

int main() {
    storage = dslink_storage_init(json_object());

    char *array[] = {
        "Hello",
        "World"
    };

    json_t *loaded = dslink_storage_traverse(storage);
    print_json(loaded);
    printf("\n");
    dslink_storage_push(storage, array, json_string("Hello World"), on_val_save, NULL);
    dslink_storage_push(storage, array, json_string("Hello World"), on_val_save, NULL);
    dslink_storage_pull(storage, array, NULL, NULL);
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
