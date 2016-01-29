#include <string.h>
#include <stdlib.h>
#include "dslink/col/map.h"
#include "dslink/err.h"

static inline
uint32_t dslink_map_hash_key(void *key, size_t len);

static inline
size_t dslink_map_index_of_key(void *key, size_t len, size_t capacity);

int dslink_map_str_cmp(void *key, void *other, size_t len) {
    return strncmp((char *) key, (char *) other, len);
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

inline
int dslink_map_init(Map *map,
                    dslink_map_key_comparator cmp,
                    dslink_map_key_len_calc calc) {
    return dslink_map_initb(map, cmp, calc, 8);
}

inline
int dslink_map_initb(Map *map,
                     dslink_map_key_comparator cmp,
                     dslink_map_key_len_calc calc,
                     size_t buckets) {
    return dslink_map_initbf(map, cmp, calc, buckets, 0.75F);
}

int dslink_map_initbf(Map *map,
                      dslink_map_key_comparator cmp,
                      dslink_map_key_len_calc calc,
                      size_t buckets, float loadFactor) {
    if (!map) {
        return 1;
    }
    memset(map, 0, sizeof(Map));
    map->table = calloc(buckets, sizeof(MapNode*));
    if (!map->table) {
        return DSLINK_ALLOC_ERR;
    }
    list_init(&map->list);
    map->max_load_factor = loadFactor;
    map->capacity = buckets;
    map->cmp = cmp;
    map->key_len_calc = calc;
    return 0;
}

static
int dslink_map_get_raw_node(Map *map, MapNode **node,
                                 void *key, size_t len) {
    int ret = 0;
    size_t index = dslink_map_index_of_key(key, len, map->capacity);
    *node = map->table[index];
    if (!(*node)) {
        *node = map->table[index] = malloc(sizeof(MapNode));
        if (*node) {
            (*node)->entry = malloc(sizeof(MapEntry));
            if (!(*node)->entry) {
                map->table[index] = NULL;
                free(*node);
                *node = NULL;
                goto exit;
            }
            (*node)->entry->node = *node;
            (*node)->entry->key = key;

            (*node)->next = NULL;
            (*node)->prev = NULL;
        }
    } else {
        while (1) {
            if (map->cmp((*node)->entry->key, key, len) == 0) {
                return 1;
            }
            MapNode *tmp = (*node)->next;
            if (tmp == NULL) {
                tmp = malloc(sizeof(MapNode));
                if (!tmp) {
                    *node = NULL;
                    break;
                }
                tmp->entry = malloc(sizeof(MapEntry));
                if (!tmp->entry) {
                    free(*node);
                    *node = NULL;
                    break;
                }

                tmp->entry->key = key;
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
    map->items++;
    insert_list_node(&map->list, (*node)->entry);
    return ret;
}

static
int dslink_map_rehash_table(Map *map) {
    size_t oldCapacity = map->capacity;
    MapNode **oldTable = map->table;

    size_t newCapacity = oldCapacity * 2;
    MapNode **newTable = calloc(newCapacity, sizeof(MapNode*));
    if (!newTable) {
        return DSLINK_ALLOC_ERR;
    }

    map->capacity = newCapacity;
    map->table = newTable;
    for (MapEntry *entry = (MapEntry *) map->list.head.next;
         (void *)entry != &map->list.head; entry = entry->next) {
        size_t len = map->key_len_calc(entry->key);
        size_t index = dslink_map_index_of_key(entry->key, len, newCapacity);
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
    free(oldTable);
    return 0;
}

int dslink_map_set(Map *map, void *key, void **value) {
    size_t len = map->key_len_calc(key);
    return dslink_map_setl(map, key, len, value);
}

int dslink_map_setl(Map *map, void *key, size_t len, void **value) {
    int ret;
    const float loadFactor = (float) map->items / map->capacity;
    if (loadFactor >= map->max_load_factor) {
        if ((ret = dslink_map_rehash_table(map)) != 0) {
            *value = NULL;
            return ret;
        }
    }

    MapNode *node = NULL;
    if ((ret = dslink_map_get_raw_node(map, &node, key, len)) != 0) {
        if (ret == DSLINK_ALLOC_ERR) {
            *value = NULL;
            return ret;
        }
    }

    void *tmp = node->entry->value;
    node->entry->value = *value;
    if (ret == 0) {
        *value = NULL;
    } else {
        *value = tmp;
    }
    return 0;
}

void *dslink_map_remove(Map *map, void **key) {
    size_t len = map->key_len_calc(*key);
    return dslink_map_removel(map, key, len);
}

void *dslink_map_removel(Map *map, void **key, size_t len) {
    size_t index = dslink_map_index_of_key(*key, len, map->capacity);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key, *key, len) != 0) {
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
        *key = node->entry->key;
        void *value = node->entry->value;
        free_list_node(node->entry);
        free(node);
        map->items--;
        return value;
    }
    *key = NULL;
    return NULL;
}

int dslink_map_contains(Map *map, void *key) {
    size_t len = map->key_len_calc(key);
    return dslink_map_containsl(map, key, len);
}

int dslink_map_containsl(Map *map, void *key, size_t len) {
    size_t index = dslink_map_index_of_key(key, len, map->capacity);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key, key, len) == 0) {
            return 1;
        }
    }
    return 0;
}

void *dslink_map_get(Map *map, void *key) {
    size_t len = map->key_len_calc(key);
    return dslink_map_getl(map, key, len);
}

void *dslink_map_getl(Map *map, void *key, size_t len) {
    size_t index = dslink_map_index_of_key(key, len, map->capacity);
    for (MapNode *node = map->table[index]; node != NULL; node = node->next) {
        if (map->cmp(node->entry->key, key, len) == 0) {
            return node->entry->value;
        }
    }
    return NULL;
}

static inline
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
size_t dslink_map_index_of_key(void *key, size_t len, size_t capacity) {
    return dslink_map_hash_key(key, len) % capacity;
}
