#ifndef SDK_DSLINK_C_MAP_H
#define SDK_DSLINK_C_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "list.h"

#define DSLINK_MAP_FREE(map, freeFunc) \
    for (MapEntry *entry = (MapEntry *) (map)->list.head.next; (void*)entry != &(map)->list.head;) { \
        { freeFunc; } \
        MapEntry *tmp = entry->next; \
        dslink_free(entry->node); \
        dslink_free(entry); \
        entry = tmp; \
    } \
    if ((map)->table) dslink_free((map)->table)

#define dslink_map_foreach(map) \
    for (MapEntry *entry = (map) ? ((MapEntry *) (map)->list.head.next) : NULL; \
        entry && (void *)entry != &(map)->list.head; entry = entry->next)

typedef int (*dslink_map_key_comparator)(void *key, void *other, size_t len);
typedef size_t (*dslink_map_key_len_calc)(void *key);

typedef struct MapEntry {
    struct MapEntry *prev;
    struct MapEntry *next;
    List *list;

    void *key;
    void *value;
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

    List list;
} Map;

/// Default comparator functions

int dslink_map_str_cmp(void *key, void *other, size_t len);
size_t dslink_map_str_key_len_cal(void *key);

int dslink_map_uint32_cmp(void *key, void *other, size_t len);
size_t dslink_map_uint32_key_len_cal(void *key);

///

int dslink_map_init(Map *map,
                    dslink_map_key_comparator cmp,
                    dslink_map_key_len_calc calc);
int dslink_map_initb(Map *map,
                     dslink_map_key_comparator cmp,
                     dslink_map_key_len_calc calc,
                     size_t buckets);
int dslink_map_initbf(Map *map,
                      dslink_map_key_comparator cmp,
                      dslink_map_key_len_calc calc,
                      size_t buckets, float loadFactor);

/**
 * \param value Value to set. If the value was overwritten then it will be
 *              be set to the previous value. Otherwise it will be set to NULL
 *              upon completion.
 */
int dslink_map_set(Map *map, void *key, void **value);
int dslink_map_setl(Map *map, void *key, size_t len, void **value);

/**
 * \param key Key to remove. Upon removal, the key will be set to the original
 *            key. This allows for freeing the original key as well the
 *            associated value.
 */
void *dslink_map_remove(Map *map, void **key);
void *dslink_map_removel(Map *map, void **key, size_t len);

int dslink_map_contains(Map *map, void *key);
int dslink_map_containsl(Map *map, void *key, size_t len);

void *dslink_map_get(Map *map, void *key);
void *dslink_map_getl(Map *map, void *key, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_MAP_H
