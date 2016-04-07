#include <dslink/storage/storage.h>
#include <uv.h>

StorageProvider *storage;

static
void print_json(json_t *json) {
    char *encoded = json_dumps(json, JSON_INDENT(2) | JSON_ENCODE_ANY);
    printf("%s", encoded);
}

static
void on_got_value(json_t *val, void *data) {
    (void) data;

    print_json(val);
    printf("\n");
}

int main() {
    storage = dslink_storage_init(json_object());

    json_t *loaded = dslink_storage_traverse(storage);
    print_json(loaded);
    printf("\n");

    dslink_storage_store(storage, "Hello", "World", json_string("Hello World"), NULL, NULL);
    dslink_storage_recall(storage, "Hello", "World", on_got_value, NULL);

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
