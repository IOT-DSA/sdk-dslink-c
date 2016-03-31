#include <dslink/storage/storage.h>

static
void on_val_get(json_t *value, void *data) {
    (void) data;
    printf("%s\n", json_dumps(value, JSON_INDENT(2) | JSON_ENCODE_ANY));
}

int main() {
    StorageProvider *storage = dslink_storage_init(json_object());

    char *key[] = {
        "Hello",
        "World",
        NULL
    };

    dslink_storage_push(storage, key, json_string("Test"), NULL, NULL);
    dslink_storage_pull(storage, key, on_val_get, NULL);
}
