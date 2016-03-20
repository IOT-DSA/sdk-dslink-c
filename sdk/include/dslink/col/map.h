#ifndef SDK_DSLINK_C_MAP_H
#define SDK_DSLINK_C_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "dslink/mem/ref.h"
#include "list.h"

#define dslink_map_foreach(map)                                                 \
    for (MapEntry *entry = ((uintptr_t) map != (uintptr_t) NULL)                \
            ? ((MapEntry *) (map)->list.head.next) : NULL;                      \
        entry && (void *) entry != &(map)->list.head; entry = entry->next)

#define dslink_map_foreach_nonext(map)                                          \
    for (MapEntry *entry = ((uintptr_t) map != (uintptr_t) NULL)                \
            ? ((MapEntry *) (map)->list.head.next) : NULL;                      \
        entry && (void *) entry != &(map)->list.head;)

typedef int (*dslink_map_key_comparator)(void *key, void *other, size_t len);
typedef size_t (*dslink_map_key_len_calc)(void *key);
typedef uint32_t (*dslink_map_key_hash_func)(void *key, size_t len);

typedef struct MapEntry {
    struct MapEntry *prev;
    struct MapEntry *next;
    List *list;

    ref_t *key;
    ref_t *value;
    struct MapNode *node;
} MapEntry;

typedef struct MapNode {
    struct MapNode *prev;
    struct MapNode *next;

    MapEntry *entry;

} MapNode;

typedef struct Map {

    size_t size;
    size_t capacity;
    float max_load_factor;

    MapNode **table;

    // Comparator for keys to other keys.
    dslink_map_key_comparator cmp;

    // Handles calculation of the size of a key. This functionality is used
    // when the map doesn't know the key size in order to rehash the key.
    dslink_map_key_len_calc key_len_calc;

    // Gets the hash data from the key
    dslink_map_key_hash_func hash_key;

    List list;

    // prevent concurrent modification
    // right now it's only used during destroying the map
    uint8_t locked;
} Map;

/// Default comparator functions

int dslink_map_str_cmp(void *key, void *other, size_t len);
size_t dslink_map_str_key_len_cal(void *key);

int dslink_map_uint32_cmp(void *key, void *other, size_t len);
size_t dslink_map_uint32_key_len_cal(void *key);

///

uint32_t dslink_map_hash_key(void *key, size_t len);

int dslink_map_init(Map *map,
                    dslink_map_key_comparator cmp,
                    dslink_map_key_len_calc calc,
                    dslink_map_key_hash_func hash);
int dslink_map_initb(Map *map,
                     dslink_map_key_comparator cmp,
                     dslink_map_key_len_calc calc,
                     dslink_map_key_hash_func hash,
                     size_t buckets);
int dslink_map_initbf(Map *map,
                      dslink_map_key_comparator cmp,
                      dslink_map_key_len_calc calc,
                      dslink_map_key_hash_func hash,
                      size_t buckets, float loadFactor);

void dslink_map_clear(Map *map);
void dslink_map_free(Map *map);

int dslink_map_set(Map *map, ref_t *key, ref_t *value);
ref_t *dslink_map_remove_get(Map *map, void *key);
ref_t *dslink_map_removel_get(Map *map, void *key, size_t len);
void dslink_map_remove(Map *map, void *key);
void dslink_map_removel(Map *map, void *key, size_t len);

int dslink_map_contains(Map *map, void *key);
int dslink_map_containsl(Map *map, void *key, size_t len);

ref_t *dslink_map_get(Map *map, void *key);
ref_t *dslink_map_getl(Map *map, void *key, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_MAP_H
