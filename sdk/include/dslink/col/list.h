#ifndef SDK_DSLINK_C_LIST_H
#define SDK_DSLINK_C_LIST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define dslink_list_foreach(list) \
    for (ListNode *node = (list)->head.next; node != &list->head; node = node->next)

typedef struct ListNodeBase {
    struct ListNodeBase *prev;
    struct ListNodeBase *next;
    struct List *list;
} ListNodeBase;

typedef struct List {
    ListNodeBase head;
} List;

static inline
uint8_t is_list_empty(List *list) {
    return ((List*)list)->head.next == &((List*)list)->head;
}

static inline
uint8_t is_list_not_empty(List *list) {
    return list->head.next != &list->head;
}
static inline
uint8_t is_node_in_list(void *node) {
    return  ((ListNodeBase*)node)->list != NULL;
}


static inline
void insert_list_node_after(void *node, void *base) {
    ((ListNodeBase*)node)->list = ((ListNodeBase*)base)->list;
    ((ListNodeBase*)base)->next->prev = node;
    ((ListNodeBase*)node)->next = ((ListNodeBase*)base)->next;
    ((ListNodeBase*)base)->next = node;
    ((ListNodeBase*)node)->prev = base;
}

static inline
void insert_list_node_before(void *node, void *base) {
    ((ListNodeBase*)node)->list = ((ListNodeBase*)base)->list;
    ((ListNodeBase*)base)->prev->next = node;
    ((ListNodeBase*)node)->prev = ((ListNodeBase*)base)->prev;
    ((ListNodeBase*)base)->prev = node;
    ((ListNodeBase*)node)->next = base;
}

static inline
void insert_list_node(List *list, void *node) {
    insert_list_node_before(node, &list->head);
}

static inline
void *remove_list_node(void *node) {
    ((ListNodeBase*)node)->prev->next = ((ListNodeBase*)node)->next;
    ((ListNodeBase*)node)->next->prev = ((ListNodeBase*)node)->prev;
    ((ListNodeBase*)node)->list = NULL;
    return node;
}

static inline
void free_list_node(void *node) {
    ((ListNodeBase*)node)->prev->next = ((ListNodeBase*)node)->next;
    ((ListNodeBase*)node)->next->prev = ((ListNodeBase*)node)->prev;
    free(node);
}


typedef struct ListNode {
    struct ListNode *prev;
    struct ListNode *next;

    void *value;
} ListNode;



void list_init(List *list);

ListNode *dslink_list_insert(List *list, void *data);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LIST_H
