#ifndef SDK_DSLINK_C_LIST_H
#define SDK_DSLINK_C_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include "dslink/mem/mem.h"

#define dslink_list_foreach(list) \
    for (ListNodeBase *node = (list)->head.next; node != &(list)->head; node = node->next)

#define dslink_list_foreach_nonext(list) \
    for (ListNodeBase *node = (list)->head.next; node != &(list)->head;)

typedef struct ListNodeBase {
    struct ListNodeBase *prev;
    struct ListNodeBase *next;
    // prev and next are ignored when list==NULL
    struct List *list;
} ListNodeBase;

typedef struct ListNode {
    struct ListNode *prev;
    struct ListNode *next;
    struct List *list;
    void *value;
} ListNode;

typedef struct List {
    ListNodeBase head;
    size_t size;
} List;

static inline
uint8_t list_is_empty(List *list) {
    return (uint8_t)(!list || ((List*)list)->head.next == &((List*)list)->head);
}

static inline
uint8_t list_is_not_empty(List *list) {
    return (uint8_t)(list && list->head.next != &list->head);
}
static inline
uint8_t list_node_in_list(void *node) {
    return  (uint8_t)(node && ((ListNodeBase*)node)->list);
}


static inline
void list_insert_node_after(void *node, void *base) {
    if (node && base && ((ListNodeBase*)base)->list) {
        ((ListNodeBase *) node)->list = ((ListNodeBase *) base)->list;
        ((ListNodeBase *) base)->next->prev = (ListNodeBase *) node;
        ((ListNodeBase *) node)->next = ((ListNodeBase *) base)->next;
        ((ListNodeBase *) base)->next = (ListNodeBase *) node;
        ((ListNodeBase *) node)->prev = (ListNodeBase *) base;
        ((ListNodeBase *)base)->list->size++;
    }
}

static inline
void list_insert_node_before(void *node, void *base) {
    if (node && base && ((ListNodeBase*)base)->list) {
        ((ListNodeBase *) node)->list = ((ListNodeBase *) base)->list;
        ((ListNodeBase *) base)->prev->next = (ListNodeBase *) node;
        ((ListNodeBase *) node)->prev = ((ListNodeBase *) base)->prev;
        ((ListNodeBase *) base)->prev = (ListNodeBase *) node;
        ((ListNodeBase *) node)->next = (ListNodeBase *) base;
        ((ListNodeBase*)base)->list->size++;
    }
}

static inline
void list_insert_node(List *list, void *node) {
    list_insert_node_before(node, &list->head);
}

static inline
void *list_remove_node(void *node) {
    if (node && ((ListNodeBase*)node)->list) {
        ((ListNodeBase*)node)->list->size --;
        ((ListNodeBase*)node)->prev->next = ((ListNodeBase*)node)->next;
        ((ListNodeBase*)node)->next->prev = ((ListNodeBase*)node)->prev;
        ((ListNodeBase*)node)->list = NULL;
    }
    return node;
}

static inline
void list_remove_all_nodes(List *list) {
    dslink_list_foreach(list) {
        node->list = NULL;
    }
    list->head.next = &list->head;
    list->head.prev = &list->head;
    list->size = 0;
}

static inline
void list_free_node(void *node) {
    if (node) {
        if (((ListNodeBase*)node)->list) {
            ((ListNodeBase*)node)->list->size --;
            ((ListNodeBase*)node)->prev->next = ((ListNodeBase*)node)->next;
            ((ListNodeBase*)node)->next->prev = ((ListNodeBase*)node)->prev;
        }
        dslink_free(node);
    }
}

void list_init(List *list);

ListNode *dslink_list_insert(List *list, void *data);

// frees the list and all nodes
// doesn't handle node->value
void dslink_list_free(List *list);

// free children nodes
// doesn't handle node->value
void dslink_list_free_all_nodes(List *list);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LIST_H
