#include <stdlib.h>
#include <string.h>
#include "dslink/col/list.h"

void list_init(List *list) {
    list->head.list = list;
    list->head.next = &list->head;
    list->head.prev = &list->head;
}


ListNode *dslink_list_insert(List *list, void *data) {
    ListNode *node = malloc(sizeof(ListNode));
    if (!node) {
        return NULL;
    }

    list_insert_node(list, node);
    node->value = data;
    return node;
}

