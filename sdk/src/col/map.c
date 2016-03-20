#include <string.h>
#include <stdlib.h>
#include "dslink/mem/mem.h"
#include "dslink/col/map.h"
#include "dslink/err.h"

/*************************** Comparators *******************************/

int dslink_map_str_cmp(void *key, void *other, size_t len) {
    return !(strncmp((char *) key, (char *) other, len) == 0
             && strlen(key) == len);
}

size_t dslink_map_str_key_len_cal(void *key) {
    return strlen(key);
}

int dslink_map_uint32_cmp(void *key, void *other, size_t len) {
    (void) len;
    uint32_t *a = key;
    uint32_t *b = other;
    return *a != *b;
}

size_t dslink_map_uint32_key_len_cal(void *key) {
    (void) key;
    return sizeof(uint32_t);
}

/***********************************************************************/

uint32_t dslink_map_hash_key(void *key, size_t len) {
    // Jenkins hash algorithm
    uint32_t hash;
    char *c = key;
    for(hash = 0; len-- > 0;) {
        hash += *c++;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static inline
size_t dslink_map_index_of_key(Map *map, void *key, size_t len) {
    return map->hash_key(key, len) % map->capacity;
}

inline
int dslink_map_init(Map *map,
                    dslink_map_key_comparator cmp,
                    dslink_map_key_len_calc calc,
                    dslink_map_key_hash_func hash) {
    return dslink_map_initb(map, cmp, calc, hash, 8);
}

inline
int dslink_map_initb(Map *map,
                     dslink_map_key_comparator cmp,
                     dslink_map_key_len_calc calc,
                     dslink_map_key_hash_func hash,
                     size_t buckets) {
    return dslink_map_initbf(map, cmp, calc, hash, buckets, 0.75F);
}

int dslink_map_initbf(Map *map,
                      dslink_map_key_comparator cmp,
                      dslink_map_key_len_calc calc,
                      dslink_map_key_hash_func hash,
                      size_t buckets, float loadFactor) {
    if (!map) {
        return 1;
    }
    memset(map, 0, sizeof(Map));
    map->table = dslink_calloc(buckets, sizeof(MapNode*));
    if (!map->table) {
        return DSLINK_ALLOC_ERR;
    }
    list_init(&map->list);
    map->max_load_factor = loadFactor;
    map->hash_key = hash;
    map->capacity = buckets;
    map->cmp = cmp;
    map->key_len_calc = calc;
    return 0;
}

static
void dslink_map_entry_clear(Map *map) {
    for (MapEntry *entry = (MapEntry *) map->list.head.next;
         (void *) entry != &map->list.head;) {
        MapEntry *tmp = entry->next;
        dslink_decref(entry->key);
        dslink_decref(entry->value);
        dslink_free(entry->node);
        dslink_free(entry);
        entry = tmp;
    }
}

void dslink_map_free(Map *map) {
    if (!(map && map->table)) {
        return;
    }
    dslink_map_entry_clear(map);
    dslink_free(map->table);
}

void dslink_map_clear(Map *map) {
    if (!(map && map->table && map->size > 0)) {
        return;
    }
    dslink_map_entry_clear(map);
    list_init(&map->list);
    memset(map->table, 0, map->capacity * sizeof(void *));
    map->size = 0;
}

static
int dslink_map_get_raw_node(Map *map, MapNode **node, ref_t *key) {
    int ret = 0;
    size_t len = map->key_len_calc(key->data);
    size_t index = dslink_map_index_of_key(map, key->data, len);
    *node = map->table[index];
    if (!(*node)) {
        *node = map->table[index] = dslink_malloc(sizeof(MapNode));
        if (*node) {
            (*node)->entry = dslink_malloc(sizeof(MapEntry));
            if (!(*node)->entry) {
                map->table[index] = NULL;
                dslink_free(*node);
                *node = NULL;
                goto exit;
            }
            (*node)->entry->node = *node;
            (*node)->entry->key = key;
            (*node)->entry->value = NULL;

            (*node)->next = NULL;
            (*node)->prev = NULL;
        }
    } else {
        while (1) {
            if (map->cmp((*node)->entry->key->data, key->data, len) == 0) {
                dslink_decref((*node)->entry->key);
                (*node)->entry->key = key;
                return 1;
            }
            MapNode *tmp = (*node)->next;
            if (tmp == NULL) {
                tmp = dslink_malloc(sizeof(MapNode));
                if (!tmp) {
                    *node = NULL;
                    break;
                }
                tmp->entry = dslink_malloc(sizeof(MapEntry));
                if (!tmp->entry) {
                    dslink_free(*node);
                    *node = NULL;
                    break;
                }

                tmp->entry->key = key;
                tmp->entry->value = NULL;
                tmp->entry->node = tmp;

                tmp->next = NULL;
                tmp->prev = *node;

                (*node)->next = tmp;
                *node = tmp;
                break;
            }
            *node = tmp;
        }
    }

exit:
    if (!(*node)) {
        return DSLINK_ALLOC_ERR;
    }
    map->size++;
    list_insert_node(&map->list, (*node)->entry);
    return ret;
}

static
int dslink_map_rehash_table(Map *map) {
    size_t oldCapacity = map->capacity;
    MapNode **oldTable = map->table;

    size_t newCapacity = oldCapacity * 2;
    MapNode **newTable = dslink_calloc(newCapacity, sizeof(MapNode*));
    if (!newTable) {
        return DSLINK_ALLOC_ERR;
    }

    map->capacity = newCapacity;
    map->table = newTable;
    for (MapEntry *entry = (MapEntry *) map->list.head.next;
         (void *)entry != &map->list.head; entry = entry->next) {
        size_t len = map->key_len_calc(entry->key->data);
        size_t index = dslink_map_index_of_key(map, entry->key->data, len);
        MapNode *node = newTable[index];
        if (node) {
            while (1) {
                MapNode *tmp = node->next;
                if (tmp == NULL) {
                    break;
                }
                node = tmp;
            }
            node->next = entry->node;
            entry->node->prev = node;
            entry->node->next = NULL;
        } else {
            entry->node->next = NULL;
            entry->node->prev = NULL;
            newTable[index] = entry->node;
        }
    }
    dslink_free(oldTable);
    return 0;
}

int dslink_map_set(Map *map, ref_t *key, ref_t *value) {
    if (!(key && value)) {
        return 1;
    }
    int ret;
    const float loadFactor = (float) map->size / map->capacity;
    if (loadFactor >= map->max_load_factor) {
        if ((ret = dslink_map_rehash_table(map)) != 0) {
            return ret;
        }
    }

    MapNode *node = NULL;
    if ((ret = dslink_map_get_raw_node(map, &node, key)) != 0) {
        if (ret == DSLINK_ALLOC_ERR) {
            return ret;
        }
    }

    dslink_decref(node->entry->value);
    node->entry->value = value;
    return 0;
}

ref_t *dslink_map_remove_get(Map *map, void *key) {
    return dslink_map_removel_get(map, key, map->key_len_calc(key));
}

ref_t *dslink_map_removel_get(Map *map, void *key, size_t len) {
    if (!map || map->locked) {
        return NULL;
    }
    size_t index = dslink_map_index_of_key(map, key, len);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key->data, key, len) != 0) {
            continue;
        }
        if (node->prev == NULL) {
            if (node->next) {
                MapNode *tmp = node->next;
                tmp->prev = NULL;
                map->table[index] = tmp;
            } else {
                map->table[index] = NULL;
            }
        } else {
            node->prev->next = node->next;
            if (node->next) {
                node->next->prev = node->prev;
            }
        }

        ref_t *ref = node->entry->value;
        dslink_decref(node->entry->key);
        list_free_node(node->entry);
        dslink_free(node);
        map->size--;
        return ref;
    }
    return NULL;
}

void dslink_map_remove(Map *map, void *key) {
    dslink_map_removel(map, key, map->key_len_calc(key));
}

void dslink_map_removel(Map *map, void *key, size_t len) {
    if (!map || map->locked) {
        return;
    }
    ref_t *ref = dslink_map_removel_get(map, key, len);
    if (ref) {
        dslink_decref(ref);
    }
}

int dslink_map_contains(Map *map, void *key) {
    return dslink_map_containsl(map, key, map->key_len_calc(key));
}

int dslink_map_containsl(Map *map, void *key, size_t len) {
    size_t index = dslink_map_index_of_key(map, key, len);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key->data, key, len) == 0) {
            return 1;
        }
    }
    return 0;
}

ref_t *dslink_map_get(Map *map, void *key) {
    size_t len = map->key_len_calc(key);
    return dslink_map_getl(map, key, len);
}

ref_t *dslink_map_getl(Map *map, void *key, size_t len) {
    size_t index = dslink_map_index_of_key(map, key, len);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key->data, key, len) == 0) {
            return node->entry->value;
        }
    }
    return NULL;
}
