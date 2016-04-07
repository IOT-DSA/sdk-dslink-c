#include <stdlib.h>
#include "dslink/mem/mem.h"
#include "dslink/col/list.h"

void list_init(List *list) {
    list->size = 0;
    list->head.list = list;
    list->head.next = &list->head;
    list->head.prev = &list->head;
}

ListNode *dslink_list_insert(List *list, void *data) {
    ListNode *node = dslink_malloc(sizeof(ListNode));
    if (!node) {
        return NULL;
    }

    list_insert_node(list, node);
    node->value = data;
    return node;
}

void dslink_list_free(List *list) {
    for (ListNodeBase *node = (list)->head.next; node != &(list)->head;) {
        ListNodeBase *next = node->next;
        dslink_free(node);
        node = next;
    }
    dslink_free(list);
}

void dslink_list_free_all_nodes(List *list) {
    for (ListNodeBase *node = (list)->head.next; node != &(list)->head;) {
        ListNodeBase *next = node->next;
        dslink_free(node);
        node = next;
    }
    list_init(list);
}
